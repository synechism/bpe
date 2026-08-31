"""Adversarial, replay-bound qualification for frozen graders and reward policies."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import islice
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from bpe.admission import CandidateIdentity
from bpe.canonical import canonical_json_bytes, sha256_bytes, sha256_json
from bpe.corpus import normalize_repository_identity
from bpe.grading import score_evidence
from bpe.job import EvaluationJobManifest, EvaluationPlan, build_evaluation_plan
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
    SuiteManifest,
    SuiteTask,
)
from bpe.replay import ReplayError, validate_replay_manifest
from bpe.task import (
    MAX_TASK_ARTIFACT_BYTES,
    MAX_TASK_ARTIFACTS,
    MAX_TASK_TOTAL_ARTIFACT_BYTES,
    TaskBundle,
    build_scoring_contract,
)


class QualificationError(ValueError):
    """The supplied anchors do not qualify the frozen grader."""


class AnchorPartition(StrEnum):
    CALIBRATION = "calibration"
    VALIDATION = "validation"


class AnchorRole(StrEnum):
    MUTANT = "mutant"
    NO_OP = "no_op"
    DELETE_OPERATION = "delete_operation"
    HARDCODE = "hardcode"
    ZERO_WORK = "zero_work"
    PARTIAL_FIX = "partial_fix"
    REFERENCE = "reference"
    ALTERNATIVE = "alternative"


_FULL_SOLUTION_ROLES = {AnchorRole.REFERENCE, AnchorRole.ALTERNATIVE}
_BEHAVIOR_BASELINE_ROLES = {
    AnchorRole.NO_OP,
    AnchorRole.DELETE_OPERATION,
    AnchorRole.HARDCODE,
    AnchorRole.ZERO_WORK,
}
_REQUIRED_ROLES = frozenset(AnchorRole)
_ItemT = TypeVar("_ItemT")


class FrozenQualificationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class CheckIdentity(FrozenQualificationModel):
    stage: Literal[Stage.FUNCTIONAL, Stage.SEMANTICS]
    check_id: StableId


class QualificationWitness(FrozenQualificationModel):
    partition: AnchorPartition
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    check: CheckIdentity


class QualificationJobPlan(FrozenQualificationModel):
    repeat_index: Annotated[int, Field(ge=0, le=15)]
    job_manifest_sha256: Sha256


class QualificationAnchorPlan(FrozenQualificationModel):
    anchor_id: StableId
    partition: AnchorPartition
    role: AnchorRole
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    evaluation_plan_sha256: Sha256
    scoring_contract_sha256: Sha256
    candidate: CandidateIdentity
    expected_first_failure: Literal[
        Stage.VERIFIER,
        Stage.FUNCTIONAL,
        Stage.SEMANTICS,
    ] | None = None
    expected_failure_reason: StableId | None = None
    expected_failed_checks: Annotated[
        tuple[CheckIdentity, ...],
        Field(max_length=8192),
    ] = ()
    jobs: Annotated[
        tuple[QualificationJobPlan, ...],
        Field(min_length=2, max_length=16),
    ]

    @model_validator(mode="after")
    def expectation_matches_role(self) -> QualificationAnchorPlan:
        if len(self.expected_failed_checks) != len(set(self.expected_failed_checks)):
            raise ValueError("expected failed-check identities must be unique")
        indexes = [job.repeat_index for job in self.jobs]
        if indexes != list(range(len(self.jobs))):
            raise ValueError("qualification jobs must use canonical repeat indexes")
        job_digests = [job.job_manifest_sha256 for job in self.jobs]
        if len(job_digests) != len(set(job_digests)):
            raise ValueError("qualification job manifests must be unique per anchor")
        if self.role in _FULL_SOLUTION_ROLES:
            if (
                self.expected_first_failure is not None
                or self.expected_failure_reason is not None
                or self.expected_failed_checks
            ):
                raise ValueError("full-solution anchors must be strict-success expectations")
            return self
        if self.role == AnchorRole.MUTANT:
            if self.expected_first_failure != Stage.VERIFIER:
                raise ValueError("mutant anchors must be rejected by the verifier")
            if self.expected_failure_reason is None:
                raise ValueError("mutant anchors require an expected verifier reason")
            if self.expected_failed_checks:
                raise ValueError("verifier-rejected mutants cannot claim behavior checks")
            return self
        if self.expected_first_failure not in {Stage.FUNCTIONAL, Stage.SEMANTICS}:
            raise ValueError("behavior anchors must fail functional or semantic checks")
        if not self.expected_failed_checks:
            raise ValueError("behavior anchors require at least one killed witness")
        if self.expected_failure_reason is None:
            raise ValueError("behavior anchors require an expected failure reason")
        if any(
            check.stage != self.expected_first_failure
            for check in self.expected_failed_checks
        ):
            raise ValueError("killed witnesses must belong to the first failing stage")
        return self


class RewardOrderingConstraint(FrozenQualificationModel):
    better_anchor_id: StableId
    worse_anchor_id: StableId
    minimum_margin: Annotated[float, Field(ge=0, le=2)] = 0.0

    @model_validator(mode="after")
    def anchors_are_distinct(self) -> RewardOrderingConstraint:
        if self.better_anchor_id == self.worse_anchor_id:
            raise ValueError("reward ordering requires two distinct anchors")
        return self


class GraderQualificationPlan(FrozenQualificationModel):
    """Frozen calibration/validation anchors and the ordering they must induce."""

    schema_version: Literal["bpe.grader-qualification-plan.v1"] = (
        "bpe.grader-qualification-plan.v1"
    )
    qualification_id: StableId
    suite_id: StableId
    suite_manifest_sha256: Sha256
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    grader_id: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    minimum_tasks_per_partition: Literal[2] = 2
    anchors: Annotated[
        tuple[QualificationAnchorPlan, ...],
        Field(min_length=32, max_length=4096),
    ]
    witnesses: Annotated[
        tuple[QualificationWitness, ...],
        Field(min_length=2, max_length=65_536),
    ]
    reward_orderings: Annotated[
        tuple[RewardOrderingConstraint, ...],
        Field(min_length=40, max_length=65_536),
    ]

    @model_validator(mode="after")
    def matrix_is_closed_and_separated(self) -> GraderQualificationPlan:
        anchor_ids = [anchor.anchor_id for anchor in self.anchors]
        if len(anchor_ids) != len(set(anchor_ids)):
            raise ValueError("qualification anchor IDs must be unique")
        candidate_digests = [anchor.candidate.sha256 for anchor in self.anchors]
        if len(candidate_digests) != len(set(candidate_digests)):
            raise ValueError("qualification candidate digests must be globally unique")
        job_digests = [
            job.job_manifest_sha256 for anchor in self.anchors for job in anchor.jobs
        ]
        if len(job_digests) != len(set(job_digests)):
            raise ValueError("qualification job manifests must be globally unique")

        anchors_by_partition: dict[AnchorPartition, list[QualificationAnchorPlan]] = (
            defaultdict(list)
        )
        for anchor in self.anchors:
            anchors_by_partition[anchor.partition].append(anchor)
        anchors_by_task: dict[
            tuple[AnchorPartition, str, str, str],
            list[QualificationAnchorPlan],
        ] = defaultdict(list)
        for anchor in self.anchors:
            anchors_by_task[
                (
                    anchor.partition,
                    anchor.task_id,
                    anchor.task_version,
                    anchor.task_bundle_sha256,
                )
            ].append(anchor)
        for partition_task, task_anchors in anchors_by_task.items():
            roles = {anchor.role for anchor in task_anchors}
            if roles != _REQUIRED_ROLES:
                missing = sorted(role.value for role in _REQUIRED_ROLES - roles)
                raise ValueError(
                    f"qualification task {partition_task} does not cover every required role: "
                    f"{missing}"
                )
            if len(task_anchors) != len(_REQUIRED_ROLES):
                raise ValueError(
                    f"qualification task {partition_task} must contain exactly one "
                    "anchor for every required role"
                )
        for partition in AnchorPartition:
            partition_tasks = {
                _task_key(anchor)
                for anchor in anchors_by_partition[partition]
            }
            if len(partition_tasks) < self.minimum_tasks_per_partition:
                raise ValueError(
                    f"{partition.value} requires at least "
                    f"{self.minimum_tasks_per_partition} distinct tasks"
                )

        task_bundle_sets = {
            partition: {
                anchor.task_bundle_sha256
                for anchor in anchors_by_partition[partition]
            }
            for partition in AnchorPartition
        }
        if (
            task_bundle_sets[AnchorPartition.CALIBRATION]
            & task_bundle_sets[AnchorPartition.VALIDATION]
        ):
            raise ValueError("calibration and validation task bundles must be disjoint")

        contracts_by_task: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        identities_by_bundle: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        for anchor in self.anchors:
            task_identity = (anchor.task_id, anchor.task_version, anchor.task_bundle_sha256)
            contracts_by_task[task_identity].add(anchor.scoring_contract_sha256)
            identities_by_bundle[anchor.task_bundle_sha256].add(
                (anchor.task_id, anchor.task_version, anchor.scoring_contract_sha256)
            )
        if any(len(digests) != 1 for digests in contracts_by_task.values()):
            raise ValueError("one task bundle cannot be paired with multiple contracts")
        if any(len(identities) != 1 for identities in identities_by_bundle.values()):
            raise ValueError("one task-bundle digest cannot be relabeled or rebound")

        witness_keys = [
            (
                witness.partition,
                witness.task_id,
                witness.task_version,
                witness.task_bundle_sha256,
                witness.check,
            )
            for witness in self.witnesses
        ]
        if len(witness_keys) != len(set(witness_keys)):
            raise ValueError("qualification witnesses must be unique")
        task_partitions = {
            (
                anchor.partition,
                anchor.task_id,
                anchor.task_version,
                anchor.task_bundle_sha256,
            )
            for anchor in self.anchors
        }
        if any(
            (
                witness.partition,
                witness.task_id,
                witness.task_version,
                witness.task_bundle_sha256,
            )
            not in task_partitions
            for witness in self.witnesses
        ):
            raise ValueError("every witness must belong to a planned partition task")
        witness_set = set(witness_keys)
        for anchor in self.anchors:
            for check in anchor.expected_failed_checks:
                key = (
                    anchor.partition,
                    anchor.task_id,
                    anchor.task_version,
                    anchor.task_bundle_sha256,
                    check,
                )
                if key not in witness_set:
                    raise ValueError("every required killed check must be a declared witness")
        covered_by_plan = {
            (
                anchor.partition,
                anchor.task_id,
                anchor.task_version,
                anchor.task_bundle_sha256,
                check,
            )
            for anchor in self.anchors
            for check in anchor.expected_failed_checks
        }
        if covered_by_plan != witness_set:
            raise ValueError("the planned kill matrix must cover every declared witness")

        by_id = {anchor.anchor_id: anchor for anchor in self.anchors}
        relation_ids = [
            (relation.better_anchor_id, relation.worse_anchor_id)
            for relation in self.reward_orderings
        ]
        if len(relation_ids) != len(set(relation_ids)):
            raise ValueError("reward-ordering constraints must be unique")
        for relation in self.reward_orderings:
            if (
                relation.better_anchor_id not in by_id
                or relation.worse_anchor_id not in by_id
            ):
                raise ValueError("reward ordering references an unknown anchor")
            if (
                by_id[relation.better_anchor_id].partition
                != by_id[relation.worse_anchor_id].partition
            ):
                raise ValueError("reward orderings cannot cross calibration and validation")
            if _task_key(by_id[relation.better_anchor_id]) != _task_key(
                by_id[relation.worse_anchor_id]
            ):
                raise ValueError("reward orderings must stay within one task bundle")
        _validate_acyclic_ordering(anchor_ids, relation_ids)

        incoming: dict[str, set[str]] = defaultdict(set)
        outgoing: dict[str, set[str]] = defaultdict(set)
        for better, worse in relation_ids:
            incoming[worse].add(better)
            outgoing[better].add(worse)
        for anchor in self.anchors:
            if anchor.role in _FULL_SOLUTION_ROLES:
                continue
            if not any(
                by_id[better].role in _FULL_SOLUTION_ROLES
                and _task_key(by_id[better]) == _task_key(anchor)
                for better in incoming[anchor.anchor_id]
            ):
                raise ValueError(
                    f"invalid anchor {anchor.anchor_id} must rank below a full solution"
                )
            if anchor.role == AnchorRole.PARTIAL_FIX:
                outranked_roles = {
                    by_id[worse].role
                    for worse in outgoing[anchor.anchor_id]
                    if _task_key(by_id[worse]) == _task_key(anchor)
                }
                missing_baselines = _BEHAVIOR_BASELINE_ROLES - outranked_roles
                if missing_baselines:
                    missing = sorted(role.value for role in missing_baselines)
                    raise ValueError(
                        "each partial fix must rank above every behavior baseline: "
                        f"{missing}"
                    )
        return self


def _validate_acyclic_ordering(
    anchor_ids: Sequence[str],
    relations: Sequence[tuple[str, str]],
) -> None:
    outgoing: dict[str, set[str]] = {anchor_id: set() for anchor_id in anchor_ids}
    indegree: Counter[str] = Counter({anchor_id: 0 for anchor_id in anchor_ids})
    for better, worse in relations:
        outgoing[better].add(worse)
        indegree[worse] += 1
    ready = [anchor_id for anchor_id in anchor_ids if indegree[anchor_id] == 0]
    visited = 0
    while ready:
        current = ready.pop()
        visited += 1
        for child in outgoing[current]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(anchor_ids):
        raise ValueError("reward-ordering constraints must be acyclic")


class GraderQualificationAttempt(FrozenQualificationModel):
    schema_version: Literal["bpe.grader-qualification-attempt.v1"] = (
        "bpe.grader-qualification-attempt.v1"
    )
    anchor_id: StableId
    repeat_index: Annotated[int, Field(ge=0, le=15)]
    job: EvaluationJobManifest
    evidence: EvaluationEvidence
    grade: Grade
    manifest: ReplayManifest
    replay_anchor: ReplayAnchor


class QualificationReplayDigest(FrozenQualificationModel):
    repeat_index: Annotated[int, Field(ge=0, le=15)]
    request_id: StableId
    evaluation_job_manifest_sha256: Sha256
    restore_nonce: Sha256
    evidence_sha256: Sha256
    grade_sha256: Sha256
    replay_manifest_sha256: Sha256


class AnchorQualificationResult(FrozenQualificationModel):
    anchor_id: StableId
    partition: AnchorPartition
    role: AnchorRole
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    candidate: CandidateIdentity
    strict_success: bool
    first_failure: Stage | None
    training_reward: Annotated[float, Field(ge=-1, le=1)]
    failed_checks: Annotated[tuple[CheckIdentity, ...], Field(max_length=8192)]
    behavior_sha256: Sha256
    replays: Annotated[
        tuple[QualificationReplayDigest, ...],
        Field(min_length=2, max_length=16),
    ]


class WitnessCoverage(FrozenQualificationModel):
    witness: QualificationWitness
    killed_by_anchor_ids: Annotated[tuple[StableId, ...], Field(min_length=1)]


class RewardOrderingResult(FrozenQualificationModel):
    partition: AnchorPartition
    better_anchor_id: StableId
    worse_anchor_id: StableId
    better_reward: Annotated[float, Field(ge=-1, le=1)]
    worse_reward: Annotated[float, Field(ge=-1, le=1)]
    observed_margin: Annotated[float, Field(gt=0, le=2)]
    required_minimum_margin: Annotated[float, Field(ge=0, le=2)]


class GraderQualificationReport(FrozenQualificationModel):
    """A successful structural Phase 0 qualification receipt."""

    schema_version: Literal["bpe.grader-qualification-report.v1"] = (
        "bpe.grader-qualification-report.v1"
    )
    phase: Literal["phase0"] = "phase0"
    status: Literal["provisional"] = "provisional"
    authoritative: Literal[False] = False
    qualification_id: StableId
    plan_sha256: Sha256
    suite_id: StableId
    suite_manifest_sha256: Sha256
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    grader_id: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    calibration_task_bundles: Annotated[
        tuple[Sha256, ...],
        Field(min_length=2, max_length=512),
    ]
    validation_task_bundles: Annotated[
        tuple[Sha256, ...],
        Field(min_length=2, max_length=512),
    ]
    anchor_results: Annotated[
        tuple[AnchorQualificationResult, ...],
        Field(min_length=32, max_length=4096),
    ]
    witness_coverage: Annotated[
        tuple[WitnessCoverage, ...],
        Field(min_length=2, max_length=65_536),
    ]
    reward_orderings: Annotated[
        tuple[RewardOrderingResult, ...],
        Field(min_length=40, max_length=65_536),
    ]
    attempt_set_sha256: Sha256


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


def _behavior_projection(evidence: EvaluationEvidence) -> object:
    return {
        "observation_artifacts": evidence.observation_artifacts,
        "stages": tuple(
            {
                "stage": stage.stage,
                "outcome": stage.outcome,
                "reason_code": stage.reason_code,
                "exit_code": stage.exit_code,
                "facts": stage.facts,
                "artifacts": stage.artifacts,
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
                    for check in stage.checks
                ),
            }
            for stage in evidence.stages
        ),
    }


def _event_bytes(evidence: EvaluationEvidence) -> bytes:
    return b"".join(
        canonical_json_bytes(
            {
                "schema_version": "bpe.event.v1",
                "sequence": sequence,
                "stage": stage.stage.value,
                "outcome": stage.outcome.value,
                "reason_code": stage.reason_code,
                "duration_ms": stage.duration_ms,
            }
        )
        for sequence, stage in enumerate(evidence.stages)
    )


def _failed_behavior_checks(evidence: EvaluationEvidence) -> frozenset[CheckIdentity]:
    return frozenset(
        CheckIdentity(stage=stage.stage, check_id=check.check_id)
        for stage in evidence.stages
        if stage.stage in {Stage.FUNCTIONAL, Stage.SEMANTICS}
        for check in stage.checks
        if check.required and check.outcome == Outcome.FAIL
    )


def _task_key(anchor: QualificationAnchorPlan) -> tuple[str, str, str]:
    return (anchor.task_id, anchor.task_version, anchor.task_bundle_sha256)


@dataclass(frozen=True)
class _TaskAuthority:
    bundle: TaskBundle
    suite_task: SuiteTask
    evaluation_plan: EvaluationPlan
    contract: ScoringContract


def _candidate_identity(source: FileRef) -> CandidateIdentity:
    return CandidateIdentity(sha256=source.sha256, size_bytes=source.size_bytes)


def _bounded_snapshot(
    values: Iterable[_ItemT],
    *,
    expected_count: int,
    label: str,
) -> tuple[_ItemT, ...]:
    try:
        snapshot = tuple(islice(iter(values), expected_count + 1))
    except Exception as exc:
        raise QualificationError(f"cannot read qualification {label}: {exc}") from exc
    if len(snapshot) != expected_count:
        relation = "more" if len(snapshot) > expected_count else "fewer"
        raise QualificationError(
            f"qualification received {relation} {label} than the frozen plan requires"
        )
    return snapshot


def _file_refs(value: object) -> tuple[FileRef, ...]:
    references: list[FileRef] = []
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, FileRef):
            references.append(item)
        elif isinstance(item, BaseModel):
            stack.extend(item.__dict__.values())
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (tuple, list)):
            stack.extend(item)
    return tuple(references)


def _sealed_artifact_snapshot(
    bundle: TaskBundle,
) -> tuple[tuple[str, str, bytes], ...]:
    expected: dict[tuple[str, str], FileRef] = {}
    for projection, model in (("public", bundle.public), ("grader", bundle.private)):
        references = _file_refs(model)
        if len(references) > MAX_TASK_ARTIFACTS:
            raise QualificationError(
                f"qualification task {projection} projection exceeds the "
                "sealed-artifact limit"
            )
        for reference in references:
            key = (projection, reference.path)
            previous = expected.setdefault(key, reference)
            if previous != reference:
                raise QualificationError(
                    "qualification task reuses an artifact path with inconsistent identity"
                )

    if len(expected) > MAX_TASK_ARTIFACTS * 2:
        raise QualificationError("qualification task exceeds the sealed-artifact limit")

    try:
        sealed_items = tuple(
            islice(iter(bundle._artifact_bytes), len(expected) + 1)
        )
    except Exception as exc:
        raise QualificationError(
            f"cannot read qualification task sealed artifacts: {exc}"
        ) from exc
    if len(sealed_items) > len(expected):
        raise QualificationError(
            "qualification task exceeds its sealed-artifact count limit"
        )

    sealed: dict[tuple[str, str], bytes] = {}
    total_bytes = 0
    for item in sealed_items:
        if type(item) is not tuple or len(item) != 3:
            raise QualificationError("qualification task has a malformed sealed artifact")
        projection, path, content = item
        if (
            type(projection) is not str
            or projection not in {"public", "grader"}
            or type(path) is not str
            or type(content) is not bytes
        ):
            raise QualificationError("qualification task has a malformed sealed artifact")
        key = (projection, path)
        if key in sealed:
            raise QualificationError("qualification task has duplicate sealed artifacts")
        if len(content) > MAX_TASK_ARTIFACT_BYTES:
            raise QualificationError("qualification task has an oversized sealed artifact")
        total_bytes += len(content)
        if total_bytes > MAX_TASK_TOTAL_ARTIFACT_BYTES:
            raise QualificationError("qualification task sealed artifacts exceed the byte limit")
        sealed[key] = content

    if set(sealed) != set(expected):
        missing = sorted(
            f"{projection}/{path}"
            for projection, path in set(expected) - set(sealed)
        )
        unexpected = sorted(
            f"{projection}/{path}" for projection, path in set(sealed) - set(expected)
        )
        raise QualificationError(
            "qualification task sealed-artifact set is not closed: "
            f"missing={missing}, unexpected={unexpected}"
        )
    for key, reference in expected.items():
        content = sealed[key]
        if (sha256_bytes(content), len(content)) != (
            reference.sha256,
            reference.size_bytes,
        ):
            raise QualificationError(
                "qualification task sealed artifact does not match its FileRef: "
                f"{key[0]}/{key[1]}"
            )
    return tuple(
        (projection, path, sealed[(projection, path)])
        for projection, path in sorted(sealed)
    )


def _bundle_file_digests(bundle: TaskBundle) -> frozenset[str]:
    return frozenset(
        reference.sha256
        for model in (bundle.public, bundle.private)
        for reference in _file_refs(model)
    )


def _freeze_task_bundle(bundle: TaskBundle) -> TaskBundle:
    public = type(bundle.public).model_validate(bundle.public.model_dump(mode="python"))
    private = type(bundle.private).model_validate(bundle.private.model_dump(mode="python"))
    if (public.task_id, public.version) != (private.task_id, private.task_version):
        raise QualificationError("qualification task public/private identities differ")
    if public.family != "repair" or private.root_cause is None or private.mutation is None:
        raise QualificationError("grader qualification currently requires repair tasks")
    if private.provenance.original_sha256 != private.reference_source.sha256:
        raise QualificationError(
            "repair qualification provenance must bind the sealed reference source"
        )
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
        raise QualificationError("qualification task bundle digests are inconsistent")
    artifact_bytes = _sealed_artifact_snapshot(bundle)
    return TaskBundle(
        root=bundle.root,
        public=public,
        private=private,
        public_sha256=public_sha256,
        private_sha256=private_sha256,
        bundle_sha256=bundle_sha256,
        _artifact_bytes=artifact_bytes,
    )


def _validate_authority(
    plan: GraderQualificationPlan,
    suite: SuiteManifest,
    bundles: Iterable[TaskBundle],
) -> tuple[SuiteManifest, dict[str, _TaskAuthority]]:
    suite = SuiteManifest.model_validate(suite.model_dump(mode="python"))
    if (
        suite.suite_id != plan.suite_id
        or sha256_json(suite) != plan.suite_manifest_sha256
        or suite.environment_id != plan.environment_id
        or suite.family != "repair"
    ):
        raise QualificationError("qualification plan does not bind the supplied repair suite")

    required_bundles = {anchor.task_bundle_sha256 for anchor in plan.anchors}
    supplied_bundles = _bounded_snapshot(
        bundles,
        expected_count=len(required_bundles),
        label="task bundles",
    )
    frozen_bundles = tuple(_freeze_task_bundle(bundle) for bundle in supplied_bundles)
    by_bundle: dict[str, TaskBundle] = {}
    for bundle in frozen_bundles:
        if bundle.bundle_sha256 in by_bundle:
            raise QualificationError(f"duplicate task bundle: {bundle.bundle_sha256}")
        by_bundle[bundle.bundle_sha256] = bundle
    if set(by_bundle) != required_bundles:
        missing = sorted(required_bundles - set(by_bundle))
        unexpected = sorted(set(by_bundle) - required_bundles)
        raise QualificationError(
            f"qualification task-bundle set differs from plan: missing={missing}, "
            f"unexpected={unexpected}"
        )

    suite_by_bundle = {task.task_bundle_sha256: task for task in suite.tasks}
    if len(suite_by_bundle) != len(suite.tasks):
        raise QualificationError("suite task-bundle digests must be unique")
    if set(suite_by_bundle) != required_bundles:
        missing = sorted(required_bundles - set(suite_by_bundle))
        unexpected = sorted(set(suite_by_bundle) - required_bundles)
        raise QualificationError(
            "qualification suite task set differs from the plan: "
            f"missing={missing}, unexpected={unexpected}"
        )
    authority_by_bundle: dict[str, _TaskAuthority] = {}
    for digest, bundle in by_bundle.items():
        suite_task = suite_by_bundle.get(digest)
        if suite_task is None:
            raise QualificationError("qualification task bundle is not a suite member")
        try:
            evaluation_plan = build_evaluation_plan(bundle)
            contract = build_scoring_contract(bundle)
        except ValueError as exc:
            raise QualificationError(
                f"cannot derive qualification authority for {bundle.public.task_id}: {exc}"
            ) from exc
        if (
            suite_task.task_id != bundle.public.task_id
            or suite_task.task_version != bundle.public.version
            or suite_task.evaluation_plan_sha256 != sha256_json(evaluation_plan)
            or suite_task.scoring_contract_sha256 != sha256_json(contract)
            or suite_task.family != bundle.public.family
            or suite_task.root_cause != bundle.private.root_cause
            or suite_task.program_type != bundle.public.program.program_type
        ):
            raise QualificationError(
                f"suite membership does not bind task {bundle.public.task_id}"
            )
        if bundle.public.environment_id != plan.environment_id:
            raise QualificationError("qualification task uses the wrong environment")
        controls_by_kind = Counter(
            control.kind for control in bundle.private.negative_controls
        )
        expected_controls = Counter(role.value for role in _BEHAVIOR_BASELINE_ROLES)
        if controls_by_kind != expected_controls:
            raise QualificationError(
                f"qualification task {bundle.public.task_id} must seal exactly one "
                "control for every required behavior-baseline role"
            )
        if len(bundle.private.valid_alternatives) != 1:
            raise QualificationError(
                f"qualification task {bundle.public.task_id} must seal exactly one "
                "valid alternative"
            )
        if len(bundle.private.qualification_partial_fixes) != 1:
            raise QualificationError(
                f"qualification task {bundle.public.task_id} must seal exactly one "
                "partial-fix anchor"
            )
        authority_by_bundle[digest] = _TaskAuthority(
            bundle=bundle,
            suite_task=suite_task,
            evaluation_plan=evaluation_plan,
            contract=contract,
        )

    partition_by_bundle: dict[str, AnchorPartition] = {}
    for digest, authority in authority_by_bundle.items():
        split = authority.bundle.private.split
        try:
            partition = AnchorPartition(split)
        except ValueError as exc:
            raise QualificationError(
                "qualification tasks must come from calibration or validation splits"
            ) from exc
        partition_by_bundle[digest] = partition

    groups: dict[AnchorPartition, set[str]] = defaultdict(set)
    originals: dict[AnchorPartition, set[str]] = defaultdict(set)
    repositories: dict[AnchorPartition, set[str]] = defaultdict(set)
    clusters: dict[AnchorPartition, set[str]] = defaultdict(set)
    file_digests: dict[AnchorPartition, set[str]] = defaultdict(set)
    for digest, authority in authority_by_bundle.items():
        partition = partition_by_bundle[digest]
        private = authority.bundle.private
        if private.contamination_group in groups[partition]:
            raise QualificationError("qualification tasks reuse a contamination group")
        if private.provenance.original_sha256 in originals[partition]:
            raise QualificationError("qualification tasks reuse an original program")
        try:
            repository = normalize_repository_identity(private.provenance.repository)
        except ValueError as exc:
            raise QualificationError(
                f"qualification task {private.task_id} has invalid repository provenance: "
                f"{exc}"
            ) from exc
        if repository in repositories[partition]:
            raise QualificationError("qualification tasks must use distinct repositories")
        if authority.suite_task.cluster_id in clusters[partition]:
            raise QualificationError("qualification tasks reuse a suite cluster")
        groups[partition].add(private.contamination_group)
        originals[partition].add(private.provenance.original_sha256)
        repositories[partition].add(repository)
        clusters[partition].add(authority.suite_task.cluster_id)
        task_file_digests = _bundle_file_digests(authority.bundle)
        if file_digests[partition] & task_file_digests:
            raise QualificationError(
                "qualification tasks reuse an artifact digest within one partition"
            )
        file_digests[partition].update(task_file_digests)
    for label, values in (
        ("contamination group", groups),
        ("original program", originals),
        ("repository", repositories),
        ("suite cluster", clusters),
        ("artifact digest", file_digests),
    ):
        if values[AnchorPartition.CALIBRATION] & values[AnchorPartition.VALIDATION]:
            article = "an" if label in {"original program", "artifact digest"} else "a"
            raise QualificationError(
                f"calibration and validation reuse {article} {label}"
            )

    witness_by_task: dict[tuple[str, str, str], set[CheckIdentity]] = defaultdict(set)
    for witness in plan.witnesses:
        witness_by_task[
            (witness.task_id, witness.task_version, witness.task_bundle_sha256)
        ].add(witness.check)
    for anchor in plan.anchors:
        authority = authority_by_bundle[anchor.task_bundle_sha256]
        bundle = authority.bundle
        contract = authority.contract
        if anchor.partition != partition_by_bundle[bundle.bundle_sha256]:
            raise QualificationError(
                f"anchor {anchor.anchor_id} relabels the task split"
            )
        if (contract.task_id, contract.task_version, contract.task_bundle_sha256) != _task_key(
            anchor
        ):
            raise QualificationError(
                f"anchor {anchor.anchor_id} does not bind its scoring contract"
            )
        if (
            anchor.evaluation_plan_sha256 != sha256_json(authority.evaluation_plan)
            or anchor.scoring_contract_sha256 != sha256_json(contract)
        ):
            raise QualificationError(
                f"anchor {anchor.anchor_id} does not bind the derived plan and contract"
            )

        if anchor.role == AnchorRole.REFERENCE:
            expected_candidates = {_candidate_identity(bundle.private.reference_source)}
        elif anchor.role == AnchorRole.ALTERNATIVE:
            expected_candidates = {
                _candidate_identity(source)
                for source in bundle.private.valid_alternatives
            }
        elif anchor.role == AnchorRole.MUTANT:
            starter = bundle.public.starter_source
            if starter is None:
                raise QualificationError("repair qualification requires a public mutant")
            expected_candidates = {_candidate_identity(starter)}
        elif anchor.role in _BEHAVIOR_BASELINE_ROLES:
            controls = tuple(
                control
                for control in bundle.private.negative_controls
                if control.kind == anchor.role.value
            )
            expected_candidates = {
                _candidate_identity(control.source) for control in controls
            }
            if not expected_candidates:
                raise QualificationError(
                    f"task {bundle.public.task_id} lacks a declared {anchor.role.value} control"
                )
            matched_control = next(
                (
                    control
                    for control in controls
                    if _candidate_identity(control.source) == anchor.candidate
                ),
                None,
            )
            if (
                matched_control is None
                or matched_control.expected_first_failure
                != anchor.expected_first_failure
            ):
                raise QualificationError(
                    f"anchor {anchor.anchor_id} does not match its declared control"
                )
        else:
            expected_candidates = {
                _candidate_identity(bundle.private.qualification_partial_fixes[0])
            }
        if anchor.candidate not in expected_candidates:
            raise QualificationError(
                f"anchor {anchor.anchor_id} candidate does not match its sealed role"
            )

        contract_checks = {
            CheckIdentity(stage=check.stage, check_id=check.check_id)
            for check in contract.checks
            if check.required and check.stage in {Stage.FUNCTIONAL, Stage.SEMANTICS}
        }
        planned_checks = witness_by_task[_task_key(anchor)]
        if not planned_checks.issubset(contract_checks):
            raise QualificationError(
                f"planned witnesses are absent from required contract checks for "
                f"{anchor.task_id}"
            )
    return suite, authority_by_bundle


def _validate_attempt_binding(
    attempt: GraderQualificationAttempt,
    anchor: QualificationAnchorPlan,
    plan: GraderQualificationPlan,
    suite: SuiteManifest,
    authority: _TaskAuthority,
    policy: RewardPolicy,
) -> None:
    job = EvaluationJobManifest.model_validate(attempt.job.model_dump(mode="python"))
    contract = authority.contract
    evidence = attempt.evidence
    request = evidence.request
    planned_job = anchor.jobs[attempt.repeat_index]
    if (
        planned_job.repeat_index != attempt.repeat_index
        or planned_job.job_manifest_sha256 != sha256_json(job)
        or job.suite != suite
        or job.plan != authority.evaluation_plan
        or job.contract != contract
        or job.reward_policy != policy
        or job.request != request
        or job.environment != evidence.environment
        or job.harness_commit != plan.harness_commit
        or job.expected_grader_id != plan.grader_id
    ):
        raise QualificationError(
            f"attempt for {anchor.anchor_id} does not bind its precommitted evaluation job"
        )
    if (
        evidence.origin != Origin.MICROVM
        or evidence.environment.isolation != Isolation.MICROVM
    ):
        raise QualificationError("grader qualification requires microVM-shaped evidence")
    if (
        request.suite_id != plan.suite_id
        or request.suite_manifest_sha256 != plan.suite_manifest_sha256
        or (request.task_id, request.task_version, request.task_bundle_sha256)
        != _task_key(anchor)
    ):
        raise QualificationError(
            f"attempt for {anchor.anchor_id} does not bind the planned suite and task"
        )
    if (
        request.environment_id != plan.environment_id
        or sha256_json(evidence.environment) != plan.environment_sha256
        or evidence.grader_id != plan.grader_id
        or evidence.harness_commit != plan.harness_commit
    ):
        raise QualificationError(
            f"attempt for {anchor.anchor_id} does not bind the frozen grader identity"
        )
    if (
        request.candidate.sha256 != anchor.candidate.sha256
        or request.candidate.size_bytes != anchor.candidate.size_bytes
    ):
        raise QualificationError(f"attempt for {anchor.anchor_id} uses the wrong candidate")

    try:
        expected_grade = score_evidence(evidence, contract, policy)
    except ValueError as exc:
        raise QualificationError(
            f"attempt for {anchor.anchor_id} is not scoreable under its frozen contract: "
            f"{exc}"
        ) from exc
    if attempt.grade != expected_grade:
        raise QualificationError(
            f"attempt for {anchor.anchor_id} has a forged or stale grade"
        )
    try:
        manifest = validate_replay_manifest(attempt.manifest)
    except ReplayError as exc:
        raise QualificationError(
            f"attempt for {anchor.anchor_id} has an invalid replay manifest: {exc}"
        ) from exc
    replay_anchor = attempt.replay_anchor
    events_bytes = _event_bytes(evidence)
    expected_events = ArtifactRef(
        sha256=sha256_bytes(events_bytes),
        size_bytes=len(events_bytes),
        media_type="application/x-ndjson",
    )
    if (
        replay_anchor.manifest_sha256 != sha256_json(manifest)
        or replay_anchor.evidence_sha256 != sha256_json(evidence)
        or replay_anchor.grade_sha256 != sha256_json(attempt.grade)
        or replay_anchor.contract_sha256 != sha256_json(contract)
        or replay_anchor.policy_sha256 != sha256_json(policy)
        or manifest.evidence != _model_artifact(evidence)
        or manifest.grade != _model_artifact(attempt.grade)
        or manifest.contract != _model_artifact(contract)
        or manifest.policy != _model_artifact(policy)
        or manifest.events != expected_events
        or manifest.artifacts.get("candidate.c") != request.candidate
        or not _evidence_artifacts(evidence).issubset(set(manifest.artifacts.values()))
    ):
        raise QualificationError(
            f"attempt for {anchor.anchor_id} is not bound to its replay manifest and anchor"
        )


def _validate_anchor_outcome(
    anchor: QualificationAnchorPlan,
    attempts: Sequence[GraderQualificationAttempt],
    policy: RewardPolicy,
    declared_checks: frozenset[CheckIdentity],
) -> tuple[frozenset[CheckIdentity], str, float]:
    behavior_digests = {
        sha256_json(_behavior_projection(attempt.evidence)) for attempt in attempts
    }
    if len(behavior_digests) != 1:
        raise QualificationError(
            f"anchor {anchor.anchor_id} produced nondeterministic repeated behavior"
        )
    grade_projections = {
        (
            attempt.grade.comparable,
            attempt.grade.strict_success,
            attempt.grade.first_failure,
            attempt.grade.training_reward,
            _failed_behavior_checks(attempt.evidence),
        )
        for attempt in attempts
    }
    if len(grade_projections) != 1:
        raise QualificationError(
            f"anchor {anchor.anchor_id} produced nondeterministic repeated scoring"
        )
    comparable, success, first_failure, reward, failed_checks = next(iter(grade_projections))
    if comparable is not True or success is None or reward is None:
        raise QualificationError(f"anchor {anchor.anchor_id} is not comparable")
    if any(
        stage.outcome == Outcome.TIMEOUT
        for attempt in attempts
        for stage in attempt.evidence.stages
    ) or any(
        check.outcome == Outcome.TIMEOUT
        for attempt in attempts
        for stage in attempt.evidence.stages
        for check in stage.checks
    ):
        raise QualificationError(
            f"anchor {anchor.anchor_id} cannot qualify through a timeout"
        )

    if anchor.role in _FULL_SOLUTION_ROLES:
        if success is not True or first_failure is not None or reward != policy.success_reward:
            raise QualificationError(
                f"full-solution anchor {anchor.anchor_id} must pass with full reward"
            )
        if failed_checks:
            raise QualificationError(
                f"full-solution anchor {anchor.anchor_id} cannot kill a witness"
            )
    else:
        expected_failure = anchor.expected_first_failure
        if (
            success is not False
            or first_failure != expected_failure
            or attempts[0].grade.failure_reason != anchor.expected_failure_reason
            or expected_failure is None
            or any(
                attempt.grade.failure_reason != anchor.expected_failure_reason
                or attempt.grade.stage_outcomes[expected_failure] != Outcome.FAIL
                for attempt in attempts
            )
        ):
            raise QualificationError(
                f"anchor {anchor.anchor_id} did not fail at its predeclared stage"
            )
        explicit_classifications = tuple(
            (
                attempt.grade.failure_reason is not None
                and attempt.grade.failure_reason.startswith(
                    policy.explicit_hack_reason_prefix
                )
            )
            or any(
                check.required
                and check.outcome != Outcome.PASS
                and check.reason_code.startswith(policy.explicit_hack_reason_prefix)
                for stage in attempt.evidence.stages
                for check in stage.checks
            )
            for attempt in attempts
        )
        if anchor.role == AnchorRole.MUTANT:
            if reward != policy.verifier_failure_reward:
                raise QualificationError(
                    "mutant reward differs from the verifier-failure policy"
                )
            if any(explicit_classifications):
                raise QualificationError(
                    f"mutant {anchor.anchor_id} was explicitly hack-classified"
                )
        if anchor.role in _BEHAVIOR_BASELINE_ROLES and (
            not all(explicit_classifications)
            or reward != policy.explicit_hack_reward
        ):
            raise QualificationError(
                f"behavior baseline {anchor.anchor_id} was not explicitly "
                "hack-classified and penalized"
            )
        if anchor.role == AnchorRole.PARTIAL_FIX:
            if any(explicit_classifications):
                raise QualificationError(
                    f"partial fix {anchor.anchor_id} was explicitly hack-classified"
                )
            if not policy.verifier_failure_reward < reward < policy.success_reward:
                raise QualificationError(
                    f"partial fix {anchor.anchor_id} lacks an intermediate reward"
                )
        expected = frozenset(anchor.expected_failed_checks)
        if expected != failed_checks:
            missing = sorted(
                f"{check.stage.value}/{check.check_id}"
                for check in expected - failed_checks
            )
            extra = sorted(
                f"{check.stage.value}/{check.check_id}"
                for check in failed_checks - expected
            )
            raise QualificationError(
                f"anchor {anchor.anchor_id} kill matrix differs from plan: "
                f"missing={missing}, extra={extra}"
            )

    if not failed_checks.issubset(declared_checks):
        unexpected = sorted(
            f"{check.stage.value}/{check.check_id}"
            for check in failed_checks - declared_checks
        )
        raise QualificationError(
            f"anchor {anchor.anchor_id} killed undeclared witnesses: {unexpected}"
        )
    return failed_checks, next(iter(behavior_digests)), reward


def qualify_grader(
    plan: GraderQualificationPlan,
    suite: SuiteManifest,
    bundles: Iterable[TaskBundle],
    policy: RewardPolicy,
    attempts: Iterable[GraderQualificationAttempt],
) -> GraderQualificationReport:
    """Validate a frozen adversarial matrix and return a non-authoritative receipt."""

    plan = GraderQualificationPlan.model_validate(plan.model_dump(mode="python"))
    policy = RewardPolicy.model_validate(policy.model_dump(mode="python"))
    if (
        plan.reward_policy_id != policy.policy_id
        or plan.reward_policy_sha256 != sha256_json(policy)
    ):
        raise QualificationError("qualification plan does not bind the reward policy")
    suite, authority_by_bundle = _validate_authority(plan, suite, bundles)

    expected_attempt_count = sum(len(anchor.jobs) for anchor in plan.anchors)
    supplied_attempts = _bounded_snapshot(
        attempts,
        expected_count=expected_attempt_count,
        label="attempts",
    )
    frozen_attempts = tuple(
        GraderQualificationAttempt.model_validate(attempt.model_dump(mode="python"))
        for attempt in supplied_attempts
    )
    request_ids = [attempt.evidence.request.request_id for attempt in frozen_attempts]
    episode_ids = [attempt.evidence.request.episode_id for attempt in frozen_attempts]
    replay_ids = [attempt.replay_anchor.manifest_sha256 for attempt in frozen_attempts]
    job_ids = [sha256_json(attempt.job) for attempt in frozen_attempts]
    restore_nonces = [attempt.job.restore_nonce for attempt in frozen_attempts]
    if len(request_ids) != len(set(request_ids)):
        raise QualificationError("qualification attempts must have distinct request IDs")
    if len(episode_ids) != len(set(episode_ids)):
        raise QualificationError("qualification attempts must have distinct episodes")
    if len(replay_ids) != len(set(replay_ids)):
        raise QualificationError("qualification attempts must have distinct replay manifests")
    if len(job_ids) != len(set(job_ids)):
        raise QualificationError("qualification attempts must have distinct evaluation jobs")
    if len(restore_nonces) != len(set(restore_nonces)):
        raise QualificationError("qualification attempts must have distinct restore nonces")
    if any(
        attempt.evidence.request.attempt_index != 0
        or attempt.evidence.request.parent_request_id is not None
        for attempt in frozen_attempts
    ):
        raise QualificationError("qualification attempts must be independent turn-zero runs")

    witnesses_by_task: dict[
        tuple[AnchorPartition, str, str, str],
        set[CheckIdentity],
    ] = defaultdict(set)
    for witness in plan.witnesses:
        witnesses_by_task[
            (
                witness.partition,
                witness.task_id,
                witness.task_version,
                witness.task_bundle_sha256,
            )
        ].add(witness.check)
    declared_checks_by_task = {
        key: frozenset(checks) for key, checks in witnesses_by_task.items()
    }

    by_anchor: dict[str, list[GraderQualificationAttempt]] = defaultdict(list)
    for attempt in frozen_attempts:
        by_anchor[attempt.anchor_id].append(attempt)
    planned_ids = {anchor.anchor_id for anchor in plan.anchors}
    if set(by_anchor) != planned_ids:
        missing = sorted(planned_ids - set(by_anchor))
        unexpected = sorted(set(by_anchor) - planned_ids)
        raise QualificationError(
            f"qualification attempt anchors differ from plan: missing={missing}, "
            f"unexpected={unexpected}"
        )

    result_by_id: dict[str, AnchorQualificationResult] = {}
    for anchor in plan.anchors:
        anchor_attempts = by_anchor[anchor.anchor_id]
        counts = Counter(attempt.repeat_index for attempt in anchor_attempts)
        expected_counts = Counter(range(len(anchor.jobs)))
        if counts != expected_counts:
            raise QualificationError(
                f"anchor {anchor.anchor_id} repeat matrix differs from plan"
            )
        ordered_attempts = tuple(sorted(anchor_attempts, key=lambda item: item.repeat_index))
        authority = authority_by_bundle[anchor.task_bundle_sha256]
        for attempt in ordered_attempts:
            _validate_attempt_binding(
                attempt,
                anchor,
                plan,
                suite,
                authority,
                policy,
            )
        failed_checks, behavior_sha256, reward = _validate_anchor_outcome(
            anchor,
            ordered_attempts,
            policy,
            declared_checks_by_task[(anchor.partition, *_task_key(anchor))],
        )
        first = ordered_attempts[0].grade
        assert first.strict_success is not None
        assert first.training_reward is not None
        result_by_id[anchor.anchor_id] = AnchorQualificationResult(
            anchor_id=anchor.anchor_id,
            partition=anchor.partition,
            role=anchor.role,
            task_id=anchor.task_id,
            task_version=anchor.task_version,
            task_bundle_sha256=anchor.task_bundle_sha256,
            candidate=anchor.candidate,
            strict_success=first.strict_success,
            first_failure=first.first_failure,
            training_reward=reward,
            failed_checks=tuple(
                sorted(failed_checks, key=lambda check: (check.stage.value, check.check_id))
            ),
            behavior_sha256=behavior_sha256,
            replays=tuple(
                QualificationReplayDigest(
                    repeat_index=attempt.repeat_index,
                    request_id=attempt.evidence.request.request_id,
                    evaluation_job_manifest_sha256=sha256_json(attempt.job),
                    restore_nonce=attempt.job.restore_nonce,
                    evidence_sha256=sha256_json(attempt.evidence),
                    grade_sha256=sha256_json(attempt.grade),
                    replay_manifest_sha256=attempt.replay_anchor.manifest_sha256,
                )
                for attempt in ordered_attempts
            ),
        )

    killers_by_witness: dict[
        tuple[AnchorPartition, str, str, str, CheckIdentity],
        list[str],
    ] = defaultdict(list)
    for result in result_by_id.values():
        for check in result.failed_checks:
            killers_by_witness[
                (
                    result.partition,
                    result.task_id,
                    result.task_version,
                    result.task_bundle_sha256,
                    check,
                )
            ].append(result.anchor_id)

    witness_coverage: list[WitnessCoverage] = []
    for witness in plan.witnesses:
        killed_by = tuple(
            sorted(
                killers_by_witness[
                    (
                        witness.partition,
                        witness.task_id,
                        witness.task_version,
                        witness.task_bundle_sha256,
                        witness.check,
                    )
                ]
            )
        )
        if not killed_by:
            raise QualificationError(
                f"witness {witness.check.check_id} has no observed control kill"
            )
        witness_coverage.append(
            WitnessCoverage(witness=witness, killed_by_anchor_ids=killed_by)
        )

    ordering_results: list[RewardOrderingResult] = []
    for relation in plan.reward_orderings:
        better = result_by_id[relation.better_anchor_id]
        worse = result_by_id[relation.worse_anchor_id]
        margin = better.training_reward - worse.training_reward
        if margin <= 0 or margin < relation.minimum_margin:
            raise QualificationError(
                f"reward ordering failed: {better.anchor_id} ({better.training_reward}) "
                f"must outrank {worse.anchor_id} ({worse.training_reward}) by at least "
                f"{relation.minimum_margin}"
            )
        ordering_results.append(
            RewardOrderingResult(
                partition=better.partition,
                better_anchor_id=better.anchor_id,
                worse_anchor_id=worse.anchor_id,
                better_reward=better.training_reward,
                worse_reward=worse.training_reward,
                observed_margin=margin,
                required_minimum_margin=relation.minimum_margin,
            )
        )

    ordered_attempts = tuple(
        sorted(
            frozen_attempts,
            key=lambda attempt: (attempt.anchor_id, attempt.repeat_index),
        )
    )
    task_bundles = {
        partition: tuple(
            sorted(
                {
                    anchor.task_bundle_sha256
                    for anchor in plan.anchors
                    if anchor.partition == partition
                }
            )
        )
        for partition in AnchorPartition
    }
    return GraderQualificationReport(
        qualification_id=plan.qualification_id,
        plan_sha256=sha256_json(plan),
        suite_id=plan.suite_id,
        suite_manifest_sha256=plan.suite_manifest_sha256,
        reward_policy_id=policy.policy_id,
        reward_policy_sha256=sha256_json(policy),
        environment_id=plan.environment_id,
        environment_sha256=plan.environment_sha256,
        grader_id=plan.grader_id,
        harness_commit=plan.harness_commit,
        calibration_task_bundles=task_bundles[AnchorPartition.CALIBRATION],
        validation_task_bundles=task_bundles[AnchorPartition.VALIDATION],
        anchor_results=tuple(result_by_id[anchor.anchor_id] for anchor in plan.anchors),
        witness_coverage=tuple(witness_coverage),
        reward_orderings=tuple(ordering_results),
        attempt_set_sha256=sha256_json(ordered_attempts),
    )


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "grader-qualification-plan-v1.json": GraderQualificationPlan,
    "grader-qualification-attempt-v1.json": GraderQualificationAttempt,
    "grader-qualification-report-v1.json": GraderQualificationReport,
}


__all__ = [
    "JSON_SCHEMAS",
    "AnchorPartition",
    "AnchorQualificationResult",
    "AnchorRole",
    "CheckIdentity",
    "GraderQualificationAttempt",
    "GraderQualificationPlan",
    "GraderQualificationReport",
    "QualificationAnchorPlan",
    "QualificationError",
    "QualificationReplayDigest",
    "QualificationWitness",
    "RewardOrderingConstraint",
    "RewardOrderingResult",
    "WitnessCoverage",
    "qualify_grader",
]
