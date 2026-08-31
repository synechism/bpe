"""Fail-closed, provisional dynamic admission over replay-bound evidence."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from bpe.canonical import canonical_json_bytes, sha256_bytes, sha256_json
from bpe.grading import score_evidence
from bpe.models import (
    ArtifactRef,
    EvaluationEvidence,
    FileRef,
    Grade,
    Isolation,
    Origin,
    Outcome,
    ReplayAnchor,
    ReplayManifest,
    RewardPolicy,
    ScoringContract,
    Sha256,
    StableId,
    Stage,
)
from bpe.task import TaskBundle, build_scoring_contract


class AdmissionError(ValueError):
    """The supplied dynamic evidence does not satisfy the frozen admission plan."""


class AdmissionRole(StrEnum):
    ORIGINAL = "original"
    REVERT = "revert"
    ALTERNATIVE = "alternative"
    PUBLIC_MUTANT = "public_mutant"
    NEGATIVE_CONTROL = "negative_control"


class FrozenAdmissionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
    )


class CandidateIdentity(FrozenAdmissionModel):
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]


class PlannedNegativeControl(FrozenAdmissionModel):
    control_id: StableId
    candidate: CandidateIdentity
    expected_first_failure: Literal[Stage.FUNCTIONAL, Stage.SEMANTICS]


class AdmissionPlan(FrozenAdmissionModel):
    """Precommitted identity and exact repair-task role matrix."""

    schema_version: Literal["bpe.admission-plan.v1"] = "bpe.admission-plan.v1"
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    scoring_contract_sha256: Sha256
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    grader_id: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    original_repeats: Annotated[int, Field(ge=2, le=64)] = 2
    reference_candidate: CandidateIdentity
    public_mutant_candidate: CandidateIdentity
    alternative_candidates: Annotated[
        tuple[CandidateIdentity, ...], Field(min_length=1, max_length=1024)
    ]
    negative_controls: Annotated[
        tuple[PlannedNegativeControl, ...], Field(min_length=1, max_length=1024)
    ]

    @model_validator(mode="after")
    def role_matrix_is_unique(self) -> AdmissionPlan:
        alternatives = [
            (candidate.sha256, candidate.size_bytes)
            for candidate in self.alternative_candidates
        ]
        if len(alternatives) != len(set(alternatives)):
            raise ValueError("planned alternative candidates must be unique")
        controls = [control.control_id for control in self.negative_controls]
        if len(controls) != len(set(controls)):
            raise ValueError("planned negative-control IDs must be unique")
        control_candidates = [
            (control.candidate.sha256, control.candidate.size_bytes)
            for control in self.negative_controls
        ]
        if len(control_candidates) != len(set(control_candidates)):
            raise ValueError("planned negative-control candidates must be unique")
        reference = (
            self.reference_candidate.sha256,
            self.reference_candidate.size_bytes,
        )
        mutant = (
            self.public_mutant_candidate.sha256,
            self.public_mutant_candidate.size_bytes,
        )
        all_singletons = {reference, mutant, *alternatives, *control_candidates}
        expected_singletons = 2 + len(alternatives) + len(control_candidates)
        if len(all_singletons) != expected_singletons:
            raise ValueError(
                "candidate identities may only repeat across original and revert roles"
            )
        return self


class AdmissionAttempt(FrozenAdmissionModel):
    """One role-labelled replay receipt supplied to the admission gate."""

    schema_version: Literal["bpe.admission-attempt.v1"] = "bpe.admission-attempt.v1"
    role: AdmissionRole
    control_id: StableId | None = None
    evidence: EvaluationEvidence
    grade: Grade
    manifest: ReplayManifest
    anchor: ReplayAnchor

    @model_validator(mode="after")
    def control_identity_matches_role(self) -> AdmissionAttempt:
        if self.role == AdmissionRole.NEGATIVE_CONTROL and self.control_id is None:
            raise ValueError("negative-control attempts require control_id")
        if self.role != AdmissionRole.NEGATIVE_CONTROL and self.control_id is not None:
            raise ValueError("only negative-control attempts may carry control_id")
        return self


class AdmissionReplayDigest(FrozenAdmissionModel):
    role: AdmissionRole
    control_id: StableId | None = None
    request_id: StableId
    candidate_sha256: Sha256
    evidence_sha256: Sha256
    grade_sha256: Sha256
    replay_manifest_sha256: Sha256


class AdmissionReport(FrozenAdmissionModel):
    """A successful Phase 0 contract check, never an authoritative admission."""

    schema_version: Literal["bpe.admission-report.v1"] = "bpe.admission-report.v1"
    phase: Literal["phase0"] = "phase0"
    status: Literal["provisional"] = "provisional"
    authoritative: Literal[False] = False
    fresh_snapshot_instances_verified: Literal[False] = False
    plan_sha256: Sha256
    task_id: StableId
    task_version: StableId
    public_task_sha256: Sha256
    private_grader_sha256: Sha256
    task_bundle_sha256: Sha256
    scoring_contract_sha256: Sha256
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    grader_id: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    reference_behavior_sha256: Sha256
    attempt_set_sha256: Sha256
    replays: Annotated[tuple[AdmissionReplayDigest, ...], Field(min_length=1)]


def _frozen_bundle(bundle: TaskBundle) -> TaskBundle:
    public = type(bundle.public).model_validate(bundle.public.model_dump(mode="python"))
    private = type(bundle.private).model_validate(bundle.private.model_dump(mode="python"))
    if public.task_id != private.task_id or public.version != private.task_version:
        raise AdmissionError("public and private task identities differ")
    if public.family == "repair" and (
        private.root_cause is None or private.mutation is None
    ):
        raise AdmissionError("repair task admission requires mutation metadata")
    if public.family == "generation" and (
        private.root_cause is not None or private.mutation is not None
    ):
        raise AdmissionError("generation task cannot carry repair mutation metadata")
    public_sha256 = sha256_json(public)
    private_sha256 = sha256_json(private)
    bundle_sha256 = sha256_json(
        {
            "schema_version": "bpe.task-bundle.v1",
            "public_sha256": public_sha256,
            "private_sha256": private_sha256,
        }
    )
    if (
        public_sha256 != bundle.public_sha256
        or private_sha256 != bundle.private_sha256
        or bundle_sha256 != bundle.bundle_sha256
    ):
        raise AdmissionError("task bundle metadata does not match its content digests")
    return TaskBundle(
        root=bundle.root,
        public=public,
        private=private,
        public_sha256=public_sha256,
        private_sha256=private_sha256,
        bundle_sha256=bundle_sha256,
    )


def _candidate_identity(source: FileRef) -> CandidateIdentity:
    return CandidateIdentity(sha256=source.sha256, size_bytes=source.size_bytes)


def _candidate_matches(candidate: ArtifactRef, expected: CandidateIdentity) -> bool:
    return (candidate.sha256, candidate.size_bytes) == (
        expected.sha256,
        expected.size_bytes,
    )


def _model_artifact(value: BaseModel) -> ArtifactRef:
    raw = canonical_json_bytes(value)
    return ArtifactRef(
        sha256=sha256_bytes(raw),
        size_bytes=len(raw),
        media_type="application/json",
    )


def _evidence_artifacts(evidence: EvaluationEvidence) -> set[ArtifactRef]:
    references = {evidence.request.candidate, *evidence.observation_artifacts.values()}
    for stage in evidence.stages:
        references.update(stage.artifacts.values())
        for check in stage.checks:
            references.update(check.artifacts.values())
    return references


def _stage_behavior_projection(evidence: EvaluationEvidence, stage: Stage) -> object:
    stage_evidence = next(item for item in evidence.stages if item.stage == stage)
    return {
        "stage": stage_evidence.stage,
        "outcome": stage_evidence.outcome,
        "reason_code": stage_evidence.reason_code,
        "exit_code": stage_evidence.exit_code,
        "facts": stage_evidence.facts,
        "artifacts": stage_evidence.artifacts,
        "checks": tuple(
            {
                "check_id": check.check_id,
                "outcome": check.outcome,
                "required": check.required,
                "weight": check.weight,
                "reason_code": check.reason_code,
                "facts": check.facts,
                "artifacts": check.artifacts,
            }
            for check in stage_evidence.checks
        ),
    }


def _behavior_projection(evidence: EvaluationEvidence) -> object:
    return {
        "functional": _stage_behavior_projection(evidence, Stage.FUNCTIONAL),
        "semantics": _stage_behavior_projection(evidence, Stage.SEMANTICS),
    }


def _validate_plan(
    plan: AdmissionPlan,
    bundle: TaskBundle,
    contract: ScoringContract,
    policy: RewardPolicy,
) -> None:
    if bundle.public.family != "repair" or bundle.public.starter_source is None:
        raise AdmissionError("generation-family dynamic admission is not implemented")
    if (plan.task_id, plan.task_version, plan.task_bundle_sha256) != (
        bundle.public.task_id,
        bundle.public.version,
        bundle.bundle_sha256,
    ):
        raise AdmissionError("admission plan does not bind the task bundle")
    if (
        plan.scoring_contract_sha256 != sha256_json(contract)
        or plan.reward_policy_id != policy.policy_id
        or plan.reward_policy_sha256 != sha256_json(policy)
    ):
        raise AdmissionError("admission plan does not bind the contract and reward policy")
    if plan.environment_id != bundle.public.environment_id:
        raise AdmissionError("admission plan uses the wrong task environment")
    if plan.reference_candidate != _candidate_identity(bundle.private.reference_source):
        raise AdmissionError("admission plan has the wrong reference candidate")
    if plan.public_mutant_candidate != _candidate_identity(bundle.public.starter_source):
        raise AdmissionError("admission plan has the wrong public mutant candidate")

    expected_alternatives = {
        _candidate_identity(source) for source in bundle.private.valid_alternatives
    }
    if set(plan.alternative_candidates) != expected_alternatives:
        raise AdmissionError("admission plan must contain every declared alternative")

    expected_controls = {
        control.control_id: (
            _candidate_identity(control.source),
            control.expected_first_failure,
        )
        for control in bundle.private.negative_controls
    }
    planned_controls = {
        control.control_id: (
            control.candidate,
            control.expected_first_failure,
        )
        for control in plan.negative_controls
    }
    if planned_controls != expected_controls:
        raise AdmissionError("admission plan does not exactly match declared negative controls")
    if any(
        stage not in {Stage.FUNCTIONAL, Stage.SEMANTICS}
        for _, stage in expected_controls.values()
    ):
        raise AdmissionError(
            "Phase 0 negative controls must target functional or semantic behavior"
        )


def _validate_shared_identity(
    attempts: Sequence[AdmissionAttempt],
    plan: AdmissionPlan,
    bundle: TaskBundle,
    contract: ScoringContract,
    policy: RewardPolicy,
) -> None:
    contract_sha256 = sha256_json(contract)
    policy_sha256 = sha256_json(policy)
    for attempt in attempts:
        evidence = attempt.evidence
        request = evidence.request
        if (
            evidence.origin != Origin.MICROVM
            or evidence.environment.isolation != Isolation.MICROVM
        ):
            raise AdmissionError("dynamic admission requires microVM-shaped evidence")
        if (request.task_id, request.task_version, request.task_bundle_sha256) != (
            bundle.public.task_id,
            bundle.public.version,
            bundle.bundle_sha256,
        ):
            raise AdmissionError("admission evidence does not match the task bundle")
        if (
            request.environment_id != plan.environment_id
            or sha256_json(evidence.environment) != plan.environment_sha256
            or evidence.grader_id != plan.grader_id
            or evidence.harness_commit != plan.harness_commit
        ):
            raise AdmissionError("admission evidence does not match the frozen worker identity")

        expected_grade = score_evidence(evidence, contract, policy)
        if attempt.grade != expected_grade:
            raise AdmissionError("admission grade is not the deterministic score of evidence")
        manifest = attempt.manifest
        if (
            attempt.anchor.manifest_sha256 != sha256_json(manifest)
            or attempt.anchor.evidence_sha256 != sha256_json(evidence)
            or attempt.anchor.grade_sha256 != sha256_json(attempt.grade)
            or attempt.anchor.contract_sha256 != contract_sha256
            or attempt.anchor.policy_sha256 != policy_sha256
            or manifest.evidence != _model_artifact(evidence)
            or manifest.grade != _model_artifact(attempt.grade)
            or manifest.contract != _model_artifact(contract)
            or manifest.policy != _model_artifact(policy)
            or manifest.artifacts.get("candidate.c") != request.candidate
            or not _evidence_artifacts(evidence).issubset(
                set(manifest.artifacts.values())
            )
        ):
            raise AdmissionError(
                "admission replay manifest and anchor do not bind exact graded inputs"
            )


def _require_pass(attempt: AdmissionAttempt, label: str) -> None:
    if attempt.grade.strict_success is not True:
        raise AdmissionError(f"{label} must pass every strict scoring stage")


def _validate_roles(
    attempts: Sequence[AdmissionAttempt],
    plan: AdmissionPlan,
) -> str:
    by_role: dict[AdmissionRole, list[AdmissionAttempt]] = defaultdict(list)
    for attempt in attempts:
        by_role[attempt.role].append(attempt)

    expected_counts = {
        AdmissionRole.ORIGINAL: plan.original_repeats,
        AdmissionRole.REVERT: 1,
        AdmissionRole.ALTERNATIVE: len(plan.alternative_candidates),
        AdmissionRole.PUBLIC_MUTANT: 1,
        AdmissionRole.NEGATIVE_CONTROL: len(plan.negative_controls),
    }
    actual_counts = Counter(attempt.role for attempt in attempts)
    if actual_counts != Counter(expected_counts):
        raise AdmissionError(
            f"attempt role matrix differs from plan: expected={expected_counts}, "
            f"actual={dict(actual_counts)}"
        )

    reference_attempts = (
        *by_role[AdmissionRole.ORIGINAL],
        *by_role[AdmissionRole.REVERT],
    )
    for attempt in reference_attempts:
        if not _candidate_matches(
            attempt.evidence.request.candidate,
            plan.reference_candidate,
        ):
            raise AdmissionError("original and revert runs must use the reference candidate")
        _require_pass(attempt, attempt.role.value)

    planned_alternatives = set(plan.alternative_candidates)
    seen_alternatives: set[CandidateIdentity] = set()
    for attempt in by_role[AdmissionRole.ALTERNATIVE]:
        candidate = CandidateIdentity(
            sha256=attempt.evidence.request.candidate.sha256,
            size_bytes=attempt.evidence.request.candidate.size_bytes,
        )
        if candidate not in planned_alternatives:
            raise AdmissionError("alternative run uses an undeclared candidate")
        if candidate in seen_alternatives:
            raise AdmissionError("each declared alternative must appear exactly once")
        seen_alternatives.add(candidate)
        _require_pass(attempt, "alternative")
    if seen_alternatives != planned_alternatives:
        raise AdmissionError("every declared alternative must be executed")

    mutant = by_role[AdmissionRole.PUBLIC_MUTANT][0]
    if not _candidate_matches(
        mutant.evidence.request.candidate,
        plan.public_mutant_candidate,
    ):
        raise AdmissionError("public-mutant run uses the wrong candidate")
    mutant_outcomes = {
        stage.stage: stage.outcome for stage in mutant.evidence.stages
    }
    if (
        mutant.grade.first_failure != Stage.VERIFIER
        or any(
            mutant_outcomes[stage] != Outcome.PASS
            for stage in (Stage.INGEST, Stage.COMPILE, Stage.OBJECT_POLICY)
        )
        or mutant_outcomes[Stage.VERIFIER] != Outcome.FAIL
    ):
        raise AdmissionError(
            "public mutant must pass ingest, compile, and object policy, then fail verifier"
        )

    planned_controls = {control.control_id: control for control in plan.negative_controls}
    supplied_controls = by_role[AdmissionRole.NEGATIVE_CONTROL]
    supplied_counts: Counter[str] = Counter()
    for attempt in supplied_controls:
        if attempt.control_id is None:
            raise AdmissionError("negative-control attempt is missing its control ID")
        supplied_counts[attempt.control_id] += 1
    if set(supplied_counts) != set(planned_controls):
        missing = sorted(set(planned_controls) - set(supplied_counts))
        unexpected = sorted(set(supplied_counts) - set(planned_controls))
        raise AdmissionError(
            f"negative-control set differs from plan: missing={missing}, "
            f"unexpected={unexpected}"
        )
    duplicates = sorted(
        control_id for control_id, count in supplied_counts.items() if count != 1
    )
    if duplicates:
        raise AdmissionError(f"negative controls must appear exactly once: {duplicates}")
    for attempt in supplied_controls:
        assert attempt.control_id is not None
        control = planned_controls[attempt.control_id]
        if not _candidate_matches(
            attempt.evidence.request.candidate,
            control.candidate,
        ):
            raise AdmissionError(
                f"negative control {control.control_id} uses the wrong candidate"
            )
        outcomes = {stage.stage: stage.outcome for stage in attempt.evidence.stages}
        prior_stages = tuple(
            stage
            for stage in Stage
            if stage != control.expected_first_failure
        )
        target_index = list(Stage).index(control.expected_first_failure)
        reached = all(
            outcomes[stage] == Outcome.PASS
            for stage in prior_stages[:target_index]
        )
        if (
            not reached
            or outcomes[control.expected_first_failure] != Outcome.FAIL
            or attempt.grade.comparable is not True
            or attempt.grade.strict_success is not False
            or attempt.grade.first_failure != control.expected_first_failure
        ):
            raise AdmissionError(
                f"negative control {control.control_id} did not reach and fail "
                f"{control.expected_first_failure.value}"
            )

    original_projections = {
        sha256_json(_behavior_projection(attempt.evidence))
        for attempt in by_role[AdmissionRole.ORIGINAL]
    }
    if len(original_projections) != 1:
        raise AdmissionError("repeated reference runs produced nondeterministic behavior")
    reference_behavior_sha256 = next(iter(original_projections))
    if any(
        sha256_json(_behavior_projection(attempt.evidence))
        != reference_behavior_sha256
        for attempt in by_role[AdmissionRole.REVERT]
    ):
        raise AdmissionError("revert behavior differs from the reference projection")
    return reference_behavior_sha256


def admit_task(
    bundle: TaskBundle,
    contract: ScoringContract,
    policy: RewardPolicy,
    plan: AdmissionPlan,
    attempts: Iterable[AdmissionAttempt],
) -> AdmissionReport:
    """Validate a complete repair-task matrix and return a provisional receipt."""

    bundle = _frozen_bundle(bundle)
    contract = ScoringContract.model_validate(contract.model_dump(mode="python"))
    policy = RewardPolicy.model_validate(policy.model_dump(mode="python"))
    plan = AdmissionPlan.model_validate(plan.model_dump(mode="python"))
    if contract != build_scoring_contract(bundle):
        raise AdmissionError("scoring contract is not exactly derived from the task")
    _validate_plan(plan, bundle, contract, policy)

    frozen_attempts = tuple(
        AdmissionAttempt.model_validate(attempt.model_dump(mode="python"))
        for attempt in attempts
    )
    if not frozen_attempts:
        raise AdmissionError("dynamic admission requires role-labelled attempts")

    request_ids = [attempt.evidence.request.request_id for attempt in frozen_attempts]
    replay_ids = [attempt.anchor.manifest_sha256 for attempt in frozen_attempts]
    episode_ids = [attempt.evidence.request.episode_id for attempt in frozen_attempts]
    if len(request_ids) != len(set(request_ids)):
        raise AdmissionError("admission attempts must have distinct request IDs")
    if len(replay_ids) != len(set(replay_ids)):
        raise AdmissionError("admission attempts must have distinct replay manifest IDs")
    if len(episode_ids) != len(set(episode_ids)):
        raise AdmissionError("admission attempts must be distinct episodes")
    if any(
        attempt.evidence.request.attempt_index != 0
        or attempt.evidence.request.parent_request_id is not None
        for attempt in frozen_attempts
    ):
        raise AdmissionError("admission attempts must be independent turn-zero runs")

    _validate_shared_identity(frozen_attempts, plan, bundle, contract, policy)
    reference_behavior_sha256 = _validate_roles(frozen_attempts, plan)

    ordered = tuple(
        sorted(
            frozen_attempts,
            key=lambda attempt: (
                attempt.role.value,
                attempt.control_id or "",
                attempt.evidence.request.candidate.sha256,
                attempt.evidence.request.request_id,
            ),
        )
    )
    replays = tuple(
        AdmissionReplayDigest(
            role=attempt.role,
            control_id=attempt.control_id,
            request_id=attempt.evidence.request.request_id,
            candidate_sha256=attempt.evidence.request.candidate.sha256,
            evidence_sha256=sha256_json(attempt.evidence),
            grade_sha256=sha256_json(attempt.grade),
            replay_manifest_sha256=attempt.anchor.manifest_sha256,
        )
        for attempt in ordered
    )
    return AdmissionReport(
        plan_sha256=sha256_json(plan),
        task_id=bundle.public.task_id,
        task_version=bundle.public.version,
        public_task_sha256=bundle.public_sha256,
        private_grader_sha256=bundle.private_sha256,
        task_bundle_sha256=bundle.bundle_sha256,
        scoring_contract_sha256=sha256_json(contract),
        reward_policy_id=policy.policy_id,
        reward_policy_sha256=sha256_json(policy),
        environment_id=plan.environment_id,
        environment_sha256=plan.environment_sha256,
        grader_id=plan.grader_id,
        harness_commit=plan.harness_commit,
        reference_behavior_sha256=reference_behavior_sha256,
        attempt_set_sha256=sha256_json(ordered),
        replays=replays,
    )
