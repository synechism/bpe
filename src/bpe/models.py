"""Strict, frozen data contracts for BPE grading."""

from __future__ import annotations

import math
from enum import StrEnum
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
StableId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,127}$")]


def _finite_json_value(value: JsonValue) -> JsonValue:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON values must contain only finite numbers")
    if isinstance(value, list):
        for child in value:
            _finite_json_value(child)
    elif isinstance(value, dict):
        for child in value.values():
            _finite_json_value(child)
    return value


FiniteJsonValue = Annotated[JsonValue, AfterValidator(_finite_json_value)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
    )


class Stage(StrEnum):
    INGEST = "ingest"
    COMPILE = "compile"
    OBJECT_POLICY = "object_policy"
    VERIFIER = "verifier"
    FUNCTIONAL = "functional"
    SEMANTICS = "semantics"


STAGE_ORDER: tuple[Stage, ...] = (
    Stage.INGEST,
    Stage.COMPILE,
    Stage.OBJECT_POLICY,
    Stage.VERIFIER,
    Stage.FUNCTIONAL,
    Stage.SEMANTICS,
)


class Outcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    INFRA_ERROR = "infra_error"
    UNSUPPORTED = "unsupported"


class Origin(StrEnum):
    MICROVM = "microvm"
    NATIVE_LINUX = "native_linux"
    RECORDED = "recorded"
    SYNTHETIC = "synthetic"


class Isolation(StrEnum):
    MICROVM = "microvm"
    NATIVE_LINUX = "native_linux"
    SYNTHETIC = "synthetic"


class ArtifactRef(FrozenModel):
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    media_type: Annotated[str, Field(min_length=1, max_length=127)] = "application/octet-stream"


class FileRef(FrozenModel):
    path: Annotated[str, Field(min_length=1, max_length=512)]
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]

    @field_validator("path")
    @classmethod
    def path_must_be_relative_and_normalized(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise ValueError("artifact paths must be normalized relative paths")
        if str(path) != value or value.startswith("/"):
            raise ValueError("artifact paths must use normalized POSIX syntax")
        return value


class CheckEvidence(FrozenModel):
    check_id: StableId
    outcome: Literal[Outcome.PASS, Outcome.FAIL, Outcome.TIMEOUT]
    required: bool = True
    weight: Annotated[float, Field(gt=0, le=1_000_000, allow_inf_nan=False)] = 1.0
    reason_code: StableId
    message: Annotated[str, Field(max_length=4096)] = ""
    facts: dict[str, FiniteJsonValue] = Field(default_factory=dict)
    artifacts: dict[str, ArtifactRef] = Field(default_factory=dict)


class StageEvidence(FrozenModel):
    stage: Stage
    outcome: Outcome
    reason_code: StableId
    message: Annotated[str, Field(max_length=4096)] = ""
    duration_ms: Annotated[int, Field(ge=0)] = 0
    exit_code: int | None = None
    checks: Annotated[tuple[CheckEvidence, ...], Field(max_length=4096)] = ()
    facts: dict[str, FiniteJsonValue] = Field(default_factory=dict)
    artifacts: dict[str, ArtifactRef] = Field(default_factory=dict)

    @model_validator(mode="after")
    def checks_must_agree_with_stage(self) -> StageEvidence:
        required = [check for check in self.checks if check.required]
        failed = [check for check in required if check.outcome != Outcome.PASS]
        check_ids = [check.check_id for check in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("check IDs must be unique within a stage")
        if self.outcome == Outcome.PASS and self.stage in {
            Stage.OBJECT_POLICY,
            Stage.FUNCTIONAL,
            Stage.SEMANTICS,
        } and not required:
            raise ValueError(f"a passing {self.stage.value} stage requires evidence checks")
        if self.outcome == Outcome.PASS and failed:
            raise ValueError("a passing stage cannot contain a failed required check")
        if self.outcome == Outcome.FAIL and required and not failed:
            raise ValueError("a failed checked stage needs a failed required check")
        if self.outcome == Outcome.SKIPPED and (self.checks or self.artifacts):
            raise ValueError("a skipped stage cannot claim checks or artifacts")
        return self

    def required_fraction(self) -> float:
        required = [check for check in self.checks if check.required]
        if not required:
            return 1.0 if self.outcome == Outcome.PASS else 0.0
        total = sum(check.weight for check in required)
        passed = sum(check.weight for check in required if check.outcome == Outcome.PASS)
        return passed / total


class EnvironmentFingerprint(FrozenModel):
    schema_version: Literal["bpe.environment.v1"] = "bpe.environment.v1"
    environment_id: StableId
    isolation: Isolation
    architecture: StableId
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    kernel_image_sha256: Sha256
    kernel_config_sha256: Sha256
    kernel_btf_sha256: Sha256
    rootfs_sha256: Sha256
    snapshot_sha256: Sha256 | None = None
    clang_version: Annotated[str, Field(min_length=1, max_length=256)]
    clang_sha256: Sha256
    libbpf_version: Annotated[str, Field(min_length=1, max_length=128)]
    libbpf_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    bpfix_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None = None
    runner_sha256: Sha256
    compile_recipe_sha256: Sha256
    normalizer_version: StableId
    normalizer_sha256: Sha256
    public_sdk_sha256: Sha256
    resource_limits_sha256: Sha256

    @model_validator(mode="after")
    def microvm_requires_snapshot_identity(self) -> EnvironmentFingerprint:
        if self.isolation == Isolation.MICROVM and self.snapshot_sha256 is None:
            raise ValueError("microVM environments require a snapshot digest")
        return self


class EvaluationRequest(FrozenModel):
    schema_version: Literal["bpe.request.v1"] = "bpe.request.v1"
    request_id: StableId
    experiment_id: StableId
    experiment_manifest_sha256: Sha256
    model_id: StableId
    model_artifact_sha256: Sha256
    checkpoint_id: StableId
    checkpoint_artifact_sha256: Sha256
    sampling_config_sha256: Sha256
    episode_id: StableId
    suite_id: StableId
    suite_manifest_sha256: Sha256
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    candidate: ArtifactRef
    environment_id: StableId
    training_seed: Annotated[int, Field(ge=0)]
    sample_index: Annotated[int, Field(ge=0)]
    generation_seed: Annotated[int, Field(ge=0)]
    attempt_index: Annotated[int, Field(ge=0)] = 0
    diagnostic_condition: Literal["none", "raw", "bpfix"] = "none"
    parent_request_id: StableId | None = None


class EvaluationEvidence(FrozenModel):
    schema_version: Literal["bpe.evidence.v1"] = "bpe.evidence.v1"
    origin: Origin
    request: EvaluationRequest
    environment: EnvironmentFingerprint
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    grader_id: Sha256
    stages: tuple[StageEvidence, ...]
    observation_artifacts: dict[str, ArtifactRef] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_pipeline(self) -> EvaluationEvidence:
        if self.request.environment_id != self.environment.environment_id:
            raise ValueError("request and evidence environment IDs differ")
        if (
            self.request.diagnostic_condition == "bpfix"
            and self.environment.bpfix_commit is None
        ):
            raise ValueError("bpfix diagnostic evidence requires a pinned bpfix commit")
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("evidence must contain every stage in canonical order")
        if self.origin == Origin.MICROVM and self.environment.isolation != Isolation.MICROVM:
            raise ValueError("microVM evidence requires a microVM fingerprint")
        if self.origin == Origin.SYNTHETIC and self.environment.isolation != Isolation.SYNTHETIC:
            raise ValueError("synthetic evidence requires a synthetic fingerprint")
        if (
            self.origin == Origin.NATIVE_LINUX
            and self.environment.isolation != Isolation.NATIVE_LINUX
        ):
            raise ValueError("native Linux evidence requires a native Linux fingerprint")

        from bpe.identity import grader_id_for

        if self.grader_id != grader_id_for(
            self.request, self.environment, self.harness_commit
        ):
            raise ValueError("grader_id does not bind this task, harness, and environment")

        stopped = False
        for item in self.stages:
            if stopped and item.outcome != Outcome.SKIPPED:
                raise ValueError("stages after the first non-pass result must be skipped")
            if not stopped and item.outcome == Outcome.SKIPPED:
                raise ValueError("a stage cannot be skipped before the pipeline stops")
            if item.outcome != Outcome.PASS:
                stopped = True
        return self


class ExpectedCheck(FrozenModel):
    stage: Literal[Stage.OBJECT_POLICY, Stage.FUNCTIONAL, Stage.SEMANTICS]
    check_id: StableId
    required: bool = True
    weight: Annotated[float, Field(gt=0, le=1_000_000, allow_inf_nan=False)] = 1.0
    input_artifacts: dict[StableId, ArtifactRef] = Field(default_factory=dict)


class ScoringContract(FrozenModel):
    schema_version: Literal["bpe.scoring-contract.v1"] = "bpe.scoring-contract.v1"
    strict_policy_id: Literal["strict-success-v1"] = "strict-success-v1"
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    checks: Annotated[tuple[ExpectedCheck, ...], Field(min_length=3, max_length=8192)]

    @model_validator(mode="after")
    def check_manifest_is_complete_and_unique(self) -> ScoringContract:
        identities = [(check.stage, check.check_id) for check in self.checks]
        if len(identities) != len(set(identities)):
            raise ValueError("scoring-contract check identities must be unique")
        for stage in (Stage.OBJECT_POLICY, Stage.FUNCTIONAL, Stage.SEMANTICS):
            if not any(check.stage == stage and check.required for check in self.checks):
                raise ValueError(f"scoring contract requires a required {stage.value} check")
        return self


class RewardPolicy(FrozenModel):
    schema_version: Literal["bpe.reward-policy.v1"] = "bpe.reward-policy.v1"
    policy_id: StableId
    description: Annotated[str, Field(min_length=1, max_length=1024)]
    ingest_failure_reward: Annotated[float, Field(ge=-1, le=1)] = -1.0
    compile_failure_reward: Annotated[float, Field(ge=-1, le=1)] = -0.5
    object_policy_failure_reward: Annotated[float, Field(ge=-1, le=1)] = -0.25
    verifier_failure_reward: Annotated[float, Field(ge=-1, le=1)] = 0.0
    functional_reward_cap: Annotated[float, Field(ge=0, le=1)] = 0.1
    semantics_reward_cap: Annotated[float, Field(ge=0, le=1)] = 0.6
    success_reward: Annotated[float, Field(ge=0, le=1)] = 1.0
    explicit_hack_reward: Annotated[float, Field(ge=-1, le=0)] = -1.0
    explicit_hack_reason_prefix: StableId = "HACK_"

    @model_validator(mode="after")
    def rewards_must_be_monotonic(self) -> RewardPolicy:
        sequence = (
            self.ingest_failure_reward,
            self.compile_failure_reward,
            self.object_policy_failure_reward,
            self.verifier_failure_reward,
            self.functional_reward_cap,
            self.semantics_reward_cap,
            self.success_reward,
        )
        if any(left > right for left, right in pairwise(sequence)):
            raise ValueError("stage rewards must be monotonically non-decreasing")
        return self


class Grade(FrozenModel):
    schema_version: Literal["bpe.grade.v1"] = "bpe.grade.v1"
    policy_id: StableId
    grader_id: Sha256
    task_id: StableId
    candidate_sha256: Sha256
    evidence_sha256: Sha256
    contract_sha256: Sha256
    comparable: bool
    strict_success: bool | None
    benchmark_score: Annotated[float, Field(ge=0, le=1)] | None
    training_reward: Annotated[float, Field(ge=-1, le=1)] | None
    first_failure: Stage | None
    failure_reason: StableId | None
    stage_outcomes: dict[Stage, Outcome]

    @model_validator(mode="after")
    def comparable_fields_are_consistent(self) -> Grade:
        if set(self.stage_outcomes) != set(STAGE_ORDER):
            raise ValueError("grade must include every canonical stage outcome")
        scored = (self.strict_success, self.benchmark_score, self.training_reward)
        if self.comparable and any(value is None for value in scored):
            raise ValueError("comparable grades require success, benchmark, and reward values")
        if not self.comparable and any(value is not None for value in scored):
            raise ValueError("incomparable grades cannot carry score values")
        if self.strict_success is True and self.benchmark_score != 1.0:
            raise ValueError("strict success must have benchmark score 1")
        if self.strict_success is False and self.benchmark_score != 0.0:
            raise ValueError("strict failure must have benchmark score 0")

        first_non_pass = next(
            (
                stage
                for stage in STAGE_ORDER
                if self.stage_outcomes[stage] != Outcome.PASS
            ),
            None,
        )
        if self.strict_success is True:
            if first_non_pass is not None or self.first_failure or self.failure_reason:
                raise ValueError("strict success cannot contain failure fields")
        else:
            if first_non_pass is None:
                raise ValueError("non-success grade requires a non-passing stage")
            if self.first_failure != first_non_pass or self.failure_reason is None:
                raise ValueError("failure fields must identify the earliest non-passing stage")
            first_outcome = self.stage_outcomes[first_non_pass]
            if self.comparable and first_outcome in {Outcome.INFRA_ERROR, Outcome.UNSUPPORTED}:
                raise ValueError("infrastructure outcomes are not comparable")
            if not self.comparable and first_outcome not in {
                Outcome.INFRA_ERROR,
                Outcome.UNSUPPORTED,
            }:
                raise ValueError("incomparable grade requires an infrastructure outcome")
        return self


class CandidateContract(FrozenModel):
    format: Literal["single_c_source"] = "single_c_source"
    max_response_bytes: Annotated[int, Field(gt=0, le=1024 * 1024)] = 65536
    fixed_filename: Literal["candidate.c"] = "candidate.c"
    allow_markdown_fence: bool = True


class ProgramContract(FrozenModel):
    program_type: StableId
    section: StableId
    entrypoint: StableId
    max_programs: Annotated[int, Field(ge=1, le=16)] = 1


class PublicTask(FrozenModel):
    schema_version: Literal["bpe.public-task.v1"] = "bpe.public-task.v1"
    task_id: StableId
    version: StableId
    family: Literal["repair", "generation"]
    prompt: FileRef
    starter_source: FileRef | None = None
    candidate_contract: CandidateContract
    program: ProgramContract
    public_sdk_id: StableId
    environment_id: StableId
    max_attempts: Annotated[int, Field(ge=1, le=16)] = 3
    whole_attempt_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 30

    @model_validator(mode="after")
    def family_matches_starter_source(self) -> PublicTask:
        if self.family == "repair" and self.starter_source is None:
            raise ValueError("repair tasks require starter source")
        if self.family == "generation" and self.starter_source is not None:
            raise ValueError("generation tasks cannot expose starter source")
        return self


class Provenance(FrozenModel):
    repository: Annotated[str, Field(min_length=1, max_length=512)]
    commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    source_path: Annotated[str, Field(min_length=1, max_length=1024)]
    license: Annotated[str, Field(min_length=1, max_length=128)]
    original_sha256: Sha256


class MutationRecord(FrozenModel):
    operator: StableId
    operator_version: StableId
    seed: Annotated[int, Field(ge=0)]
    parameters: dict[str, FiniteJsonValue] = Field(default_factory=dict)


class AssertionSpec(FrozenModel):
    assertion_id: StableId
    kind: StableId
    required: bool = True
    weight: Annotated[float, Field(gt=0, le=1_000_000, allow_inf_nan=False)] = 1.0
    expected: FiniteJsonValue | None = None


class FunctionalCase(FrozenModel):
    case_id: StableId
    driver: StableId
    input_ref: FileRef
    assertions: Annotated[tuple[AssertionSpec, ...], Field(min_length=1)]


class SemanticObligation(FrozenModel):
    obligation_id: StableId
    kind: StableId
    description: Annotated[str, Field(min_length=1, max_length=1024)]
    required: bool = True


class NegativeControl(FrozenModel):
    control_id: StableId
    kind: Literal[
        "no_op",
        "delete_operation",
        "hardcode",
        "zero_work",
        "other",
    ]
    source: FileRef
    expected_first_failure: Stage


class PrivateGrader(FrozenModel):
    schema_version: Literal["bpe.private-grader.v1"] = "bpe.private-grader.v1"
    task_id: StableId
    task_version: StableId
    split: Literal["train", "development", "calibration", "validation", "sealed_eval"]
    root_cause: StableId | None
    contamination_group: StableId
    provenance: Provenance
    mutation: MutationRecord | None
    reference_source: FileRef
    valid_alternatives: Annotated[tuple[FileRef, ...], Field(min_length=1)]
    qualification_partial_fixes: Annotated[
        tuple[FileRef, ...],
        Field(max_length=16),
    ] = ()
    functional_cases: Annotated[tuple[FunctionalCase, ...], Field(min_length=1)]
    semantic_obligations: Annotated[tuple[SemanticObligation, ...], Field(min_length=1)]
    negative_controls: Annotated[tuple[NegativeControl, ...], Field(min_length=4)]
    strict_scoring_policy_id: Literal["strict-success-v1"] = "strict-success-v1"

    @model_validator(mode="after")
    def control_ids_must_be_unique(self) -> PrivateGrader:
        control_ids = [control.control_id for control in self.negative_controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("negative control IDs must be unique")
        return self


class ReplayManifest(FrozenModel):
    schema_version: Literal["bpe.replay.v1"] = "bpe.replay.v1"
    evidence: ArtifactRef
    grade: ArtifactRef
    contract: ArtifactRef
    events: ArtifactRef
    policy: ArtifactRef
    artifacts: dict[str, ArtifactRef] = Field(default_factory=dict)


class ReplayAnchor(FrozenModel):
    manifest_sha256: Sha256
    evidence_sha256: Sha256
    grade_sha256: Sha256
    contract_sha256: Sha256
    policy_sha256: Sha256


class ReplayAnchorRegistry(FrozenModel):
    schema_version: Literal["bpe.replay-anchor-registry.v1"] = (
        "bpe.replay-anchor-registry.v1"
    )
    registry_id: StableId
    issuer: StableId
    experiment_manifest_sha256: Sha256
    anchors: Annotated[tuple[ReplayAnchor, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def manifest_anchors_are_unique(self) -> ReplayAnchorRegistry:
        manifests = [anchor.manifest_sha256 for anchor in self.anchors]
        if len(manifests) != len(set(manifests)):
            raise ValueError("replay manifest anchors must be unique")
        return self


class SuiteTask(FrozenModel):
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    evaluation_plan_sha256: Sha256
    scoring_contract_sha256: Sha256
    family: Literal["repair", "generation"]
    root_cause: StableId | None
    program_type: StableId
    cluster_id: StableId


class SuiteManifest(FrozenModel):
    schema_version: Literal["bpe.suite.v1"] = "bpe.suite.v1"
    suite_id: StableId
    strict_policy_id: Literal["strict-success-v1"] = "strict-success-v1"
    environment_id: StableId
    family: Literal["repair", "generation"]
    root_cause_taxonomy: tuple[StableId, ...] = ()
    tasks: Annotated[tuple[SuiteTask, ...], Field(min_length=1, max_length=100_000)]

    @model_validator(mode="after")
    def task_identities_are_unique(self) -> SuiteManifest:
        identities = [task.task_id for task in self.tasks]
        if len(identities) != len(set(identities)):
            raise ValueError("suite task identities must be unique")
        if len(self.root_cause_taxonomy) != len(set(self.root_cause_taxonomy)):
            raise ValueError("suite root-cause taxonomy must be unique")
        for task in self.tasks:
            if task.family != self.family:
                raise ValueError("suite cannot mix benchmark families")
            if task.family == "repair" and task.root_cause is None:
                raise ValueError("repair suite tasks require a root cause")
            if task.family == "generation" and task.root_cause is not None:
                raise ValueError("generation suite tasks cannot claim a repair root cause")
        represented = {task.root_cause for task in self.tasks if task.root_cause is not None}
        if self.family == "repair" and represented != set(self.root_cause_taxonomy):
            raise ValueError("repair suite tasks must cover the frozen root-cause taxonomy")
        if self.family == "generation" and self.root_cause_taxonomy:
            raise ValueError("generation suites cannot declare a repair root-cause taxonomy")
        return self


class SeedPlan(FrozenModel):
    training_seed: Annotated[int, Field(ge=0)]
    checkpoint_id: StableId
    checkpoint_artifact_sha256: Sha256
    generation_seeds: Annotated[tuple[Annotated[int, Field(ge=0)], ...], Field(min_length=1)]

    @model_validator(mode="after")
    def generation_seeds_are_unique(self) -> SeedPlan:
        if len(self.generation_seeds) != len(set(self.generation_seeds)):
            raise ValueError("generation seeds must be unique within a training seed")
        return self


class ExperimentManifest(FrozenModel):
    schema_version: Literal["bpe.experiment.v1"] = "bpe.experiment.v1"
    experiment_id: StableId
    suite_id: StableId
    suite_manifest_sha256: Sha256
    model_id: StableId
    model_artifact_sha256: Sha256
    sampling_config_sha256: Sha256
    diagnostic_condition: Literal["none", "raw", "bpfix"]
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_sha256: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    expected_grader_id: Sha256
    seed_plans: Annotated[tuple[SeedPlan, ...], Field(min_length=1)]
    reported_k: Annotated[tuple[Annotated[int, Field(ge=1)], ...], Field(min_length=1)]

    @model_validator(mode="after")
    def sampling_design_is_well_formed(self) -> ExperimentManifest:
        training_seeds = [plan.training_seed for plan in self.seed_plans]
        if len(training_seeds) != len(set(training_seeds)):
            raise ValueError("experiment training seeds must be unique")
        checkpoint_ids = [plan.checkpoint_id for plan in self.seed_plans]
        checkpoint_digests = [plan.checkpoint_artifact_sha256 for plan in self.seed_plans]
        if len(checkpoint_ids) != len(set(checkpoint_ids)) or len(
            checkpoint_digests
        ) != len(set(checkpoint_digests)):
            raise ValueError("training seeds must use distinct checkpoint artifacts")
        sample_counts = {len(plan.generation_seeds) for plan in self.seed_plans}
        if len(sample_counts) != 1:
            raise ValueError("every training seed must predeclare the same sample count")
        if len(self.reported_k) != len(set(self.reported_k)):
            raise ValueError("reported k values must be unique")
        samples_per_seed = next(iter(sample_counts))
        if any(k > samples_per_seed for k in self.reported_k):
            raise ValueError("reported k cannot exceed the predeclared sample count")
        return self

    @property
    def samples_per_task_seed(self) -> int:
        return len(self.seed_plans[0].generation_seeds)


class AttemptRecord(FrozenModel):
    schema_version: Literal["bpe.attempt.v1"] = "bpe.attempt.v1"
    experiment_id: StableId
    model_id: StableId
    model_artifact_sha256: Sha256
    checkpoint_id: StableId
    checkpoint_artifact_sha256: Sha256
    sampling_config_sha256: Sha256
    reward_policy_sha256: Sha256
    episode_id: StableId
    task_id: StableId
    task_version: StableId
    task_bundle_sha256: Sha256
    family: Literal["repair", "generation"]
    root_cause: StableId | None
    program_type: StableId
    cluster_id: StableId
    training_seed: Annotated[int, Field(ge=0)]
    sample_index: Annotated[int, Field(ge=0)]
    generation_seed: Annotated[int, Field(ge=0)]
    turn_index: Annotated[int, Field(ge=0)] = 0
    replay_manifest_sha256: Sha256
    evidence: EvaluationEvidence
    grade: Grade

    @model_validator(mode="after")
    def identities_match_evidence_and_grade(self) -> AttemptRecord:
        from bpe.canonical import sha256_json

        request = self.evidence.request
        if self.experiment_id != request.experiment_id:
            raise ValueError("attempt experiment identity does not match evidence")
        if (
            self.model_id,
            self.model_artifact_sha256,
            self.checkpoint_id,
            self.checkpoint_artifact_sha256,
            self.sampling_config_sha256,
            self.episode_id,
        ) != (
            request.model_id,
            request.model_artifact_sha256,
            request.checkpoint_id,
            request.checkpoint_artifact_sha256,
            request.sampling_config_sha256,
            request.episode_id,
        ):
            raise ValueError("attempt generation provenance does not match evidence")
        if (self.task_id, self.task_version, self.task_bundle_sha256) != (
            request.task_id,
            request.task_version,
            request.task_bundle_sha256,
        ):
            raise ValueError("attempt task identity does not match evidence")
        if self.grade.task_id != self.task_id:
            raise ValueError("attempt task identity does not match grade")
        if self.grade.grader_id != self.evidence.grader_id:
            raise ValueError("attempt grader identity does not match evidence")
        if self.grade.candidate_sha256 != request.candidate.sha256:
            raise ValueError("attempt candidate identity does not match evidence")
        if self.grade.evidence_sha256 != sha256_json(self.evidence):
            raise ValueError("attempt grade does not bind the supplied evidence")
        evidence_outcomes = {stage.stage: stage.outcome for stage in self.evidence.stages}
        if self.grade.stage_outcomes != evidence_outcomes:
            raise ValueError("attempt grade outcomes do not match the supplied evidence")
        if request.generation_seed != self.generation_seed:
            raise ValueError("attempt generation seed does not match the request")
        if request.training_seed != self.training_seed:
            raise ValueError("attempt training seed does not match the request")
        if request.sample_index != self.sample_index:
            raise ValueError("attempt sample index does not match the request")
        if request.attempt_index != self.turn_index:
            raise ValueError("attempt turn index does not match the request")
        if self.turn_index == 0 and request.parent_request_id is not None:
            raise ValueError("turn zero cannot have a parent request")
        if self.turn_index > 0 and request.parent_request_id is None:
            raise ValueError("interactive turns require a parent request")
        return self


class SliceScore(FrozenModel):
    name: StableId
    task_count: Annotated[int, Field(ge=0)]
    pass_at_k: Annotated[float, Field(ge=0, le=1)] | None


class TrainingSeedScore(FrozenModel):
    training_seed: Annotated[int, Field(ge=0)]
    checkpoint_id: StableId
    checkpoint_artifact_sha256: Sha256
    task_count: Annotated[int, Field(ge=1)]
    pass_at_k: Annotated[float, Field(ge=0, le=1)]


class BenchmarkReport(FrozenModel):
    schema_version: Literal["bpe.benchmark-report.v1"] = "bpe.benchmark-report.v1"
    official: Literal[False] = False
    experiment_id: StableId
    experiment_manifest_sha256: Sha256
    replay_anchor_registry_sha256: Sha256 | None
    suite_id: StableId
    suite_manifest_sha256: Sha256
    strict_policy_id: Literal["strict-success-v1"] = "strict-success-v1"
    family: Literal["repair", "generation"]
    grader_id: Sha256
    reward_policy_id: StableId
    reward_policy_sha256: Sha256
    environment_id: StableId
    environment_sha256: Sha256
    harness_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    diagnostic_condition: Literal["none", "raw", "bpfix"]
    model_id: StableId
    model_artifact_sha256: Sha256
    sampling_config_sha256: Sha256
    k: Annotated[int, Field(ge=1)]
    samples_per_task_seed: Annotated[int, Field(ge=1)]
    eligible_task_count: Annotated[int, Field(ge=0)]
    eligible_training_seed_count: Annotated[int, Field(ge=0)]
    training_seeds: tuple[Annotated[int, Field(ge=0)], ...]
    eligible_attempt_count: Annotated[int, Field(ge=0)]
    excluded_attempt_count: Annotated[int, Field(ge=0)]
    pass_at_k: Annotated[float, Field(ge=0, le=1)] | None
    root_cause_macro_pass_at_k: Annotated[float, Field(ge=0, le=1)] | None
    bootstrap_95: tuple[
        Annotated[float, Field(ge=0, le=1)],
        Annotated[float, Field(ge=0, le=1)],
    ] | None
    bootstrap_method: Literal[
        "training-seed-and-root-cause-cluster-bayesian",
        "training-seed-and-cluster-bayesian",
    ]
    bootstrap_samples: Annotated[int, Field(gt=0)]
    bootstrap_seed: Annotated[int, Field(ge=0)]
    by_root_cause: tuple[SliceScore, ...]
    by_program_type: tuple[SliceScore, ...]
    training_seed_results: tuple[TrainingSeedScore, ...]
    failure_stage_counts: dict[Stage, Annotated[int, Field(ge=0)]]
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def report_fields_are_consistent(self) -> BenchmarkReport:
        if self.bootstrap_95 and self.bootstrap_95[0] > self.bootstrap_95[1]:
            raise ValueError("bootstrap interval bounds are reversed")
        if self.eligible_task_count == 0:
            if self.pass_at_k is not None or self.root_cause_macro_pass_at_k is not None:
                raise ValueError("an empty report cannot contain pass rates")
        elif self.pass_at_k is None:
            raise ValueError("a non-empty report requires a micro pass rate")
        if self.eligible_task_count > 0 and self.bootstrap_95 is None:
            raise ValueError("a non-empty report requires a bootstrap interval")
        if self.eligible_task_count > 0 and self.eligible_training_seed_count == 0:
            raise ValueError("a non-empty report requires training-seed results")
        if self.eligible_task_count > 0 and self.family == "repair":
            if self.root_cause_macro_pass_at_k is None or not self.by_root_cause:
                raise ValueError("repair reports require root-cause metrics")
        elif self.family == "generation" and (
            self.root_cause_macro_pass_at_k is not None or self.by_root_cause
        ):
            raise ValueError("generation reports cannot claim repair root-cause metrics")
        if len(self.training_seeds) != self.eligible_training_seed_count:
            raise ValueError("training seed count does not match the recorded seeds")
        if len(self.training_seeds) != len(set(self.training_seeds)):
            raise ValueError("training seeds must be unique")
        if tuple(item.training_seed for item in self.training_seed_results) != tuple(
            self.training_seeds
        ):
            raise ValueError("training-seed result identities do not match the report")
        if any(
            item.task_count != self.eligible_task_count
            for item in self.training_seed_results
        ):
            raise ValueError("training-seed task counts do not match the report")
        expected_attempts = (
            self.eligible_task_count
            * self.eligible_training_seed_count
            * self.samples_per_task_seed
        )
        if self.eligible_attempt_count != expected_attempts:
            raise ValueError("eligible attempt count does not match the frozen sample design")
        if sum(self.failure_stage_counts.values()) > self.eligible_attempt_count:
            raise ValueError("failure-stage counts exceed eligible attempts")
        if self.eligible_task_count > 0:
            headline = self.pass_at_k
            assert headline is not None
            if sum(item.task_count for item in self.by_program_type) != self.eligible_task_count:
                raise ValueError("program-type slices do not partition the task set")
            program_micro = sum(
                item.task_count * item.pass_at_k
                for item in self.by_program_type
                if item.pass_at_k is not None
            ) / self.eligible_task_count
            seed_micro = sum(item.pass_at_k for item in self.training_seed_results) / len(
                self.training_seed_results
            )
            if abs(program_micro - headline) > 1e-12 or abs(seed_micro - headline) > 1e-12:
                raise ValueError("report slices do not reproduce the headline pass rate")
            if self.family == "repair":
                if sum(item.task_count for item in self.by_root_cause) != self.eligible_task_count:
                    raise ValueError("root-cause slices do not partition the task set")
                root_macro = sum(
                    item.pass_at_k
                    for item in self.by_root_cause
                    if item.pass_at_k is not None
                ) / len(self.by_root_cause)
                claimed_root_macro = self.root_cause_macro_pass_at_k
                assert claimed_root_macro is not None
                if abs(root_macro - claimed_root_macro) > 1e-12:
                    raise ValueError("root-cause slices do not reproduce the macro rate")
        return self


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "environment-v1.json": EnvironmentFingerprint,
    "evaluation-request-v1.json": EvaluationRequest,
    "evidence-v1.json": EvaluationEvidence,
    "scoring-contract-v1.json": ScoringContract,
    "grade-v1.json": Grade,
    "reward-policy-v1.json": RewardPolicy,
    "public-task-v1.json": PublicTask,
    "private-grader-v1.json": PrivateGrader,
    "replay-v1.json": ReplayManifest,
    "replay-anchor-registry-v1.json": ReplayAnchorRegistry,
    "suite-v1.json": SuiteManifest,
    "experiment-v1.json": ExperimentManifest,
    "attempt-v1.json": AttemptRecord,
    "benchmark-report-v1.json": BenchmarkReport,
}
