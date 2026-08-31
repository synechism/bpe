"""Closed, content-addressed preparation bundles for future microVM jobs.

Version 1 is deliberately non-executable.  It freezes and seals the exact bytes a
future worker request would need without exposing a host path, argv, environment
variable, archive entry, or dispatch method on the wire.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from bpe.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_json,
    strict_json_loads,
)
from bpe.identity import grader_id_for
from bpe.models import (
    ArtifactRef,
    AssertionSpec,
    CandidateContract,
    EnvironmentFingerprint,
    EvaluationRequest,
    ExpectedCheck,
    ExperimentManifest,
    Isolation,
    ProgramContract,
    RewardPolicy,
    ScoringContract,
    SemanticObligation,
    Sha256,
    StableId,
    Stage,
    SuiteManifest,
)
from bpe.submission import SubmissionError, extract_c_source

if TYPE_CHECKING:
    from bpe.task import TaskBundle

MAX_JOB_MANIFEST_BYTES = 256 * 1024
MAX_JOB_JSON_DEPTH = 64
MAX_JOB_JSON_NODES = 65_536
MAX_JOB_BLOBS = 256
MAX_JOB_BLOB_BYTES = 16 * 1024 * 1024
MAX_JOB_TOTAL_BLOB_BYTES = 128 * 1024 * 1024

_COMMIT = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]


class JobBundleError(ValueError):
    """A prepared evaluation job is unsafe, incomplete, or internally inconsistent."""


class _ComponentOpener(Protocol):
    """Open one already-validated bundle component relative to a pinned directory."""

    def __call__(
        self,
        name: str,
        *,
        parent_fd: int,
        root_device: int,
        directory: bool,
        label: str,
    ) -> int: ...


class _JobModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class JobBlobRef(_JobModel):
    """Physical CAS identity; semantic media types remain on their role references."""

    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=1, le=MAX_JOB_BLOB_BYTES)]


class EvaluationFunctionalCase(_JobModel):
    """A functional case with a content reference and no filesystem pathname."""

    case_id: StableId
    input: ArtifactRef
    assertions: Annotated[tuple[AssertionSpec, ...], Field(min_length=1, max_length=256)]

    @field_validator("assertions", mode="before")
    @classmethod
    def assertions_accept_a_json_array(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def assertion_ids_are_unique(self) -> Self:
        identifiers = [assertion.assertion_id for assertion in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("functional assertion IDs must be unique within a case")
        return self


class EvaluationPlan(_JobModel):
    """The exact task logic needed for one candidate evaluation."""

    schema_version: Literal["bpe.evaluation-plan.v1"]
    profile: Literal["xdp-bpf-prog-test-run-v1"]
    task_id: StableId
    task_version: StableId
    family: Literal["repair", "generation"]
    public_task_sha256: Sha256
    private_grader_sha256: Sha256
    task_bundle_sha256: Sha256
    environment_id: StableId
    candidate_contract: CandidateContract
    program: ProgramContract
    public_sdk_id: StableId
    max_attempts: Annotated[int, Field(ge=1, le=16)]
    whole_attempt_timeout_seconds: Annotated[int, Field(ge=1, le=600)]
    functional_cases: Annotated[
        tuple[EvaluationFunctionalCase, ...],
        Field(min_length=1, max_length=256),
    ]
    semantic_obligations: Annotated[
        tuple[SemanticObligation, ...],
        Field(min_length=1, max_length=1024),
    ]
    strict_scoring_policy_id: Literal["strict-success-v1"]

    @field_validator("functional_cases", "semantic_obligations", mode="before")
    @classmethod
    def sequences_accept_json_arrays(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def identities_are_unique(self) -> Self:
        if (
            self.program.program_type != "xdp"
            or self.program.section != "xdp"
            or self.program.max_programs != 1
        ):
            raise ValueError("evaluation-plan v1 supports exactly one XDP program")
        if self.candidate_contract.allow_markdown_fence:
            raise ValueError(
                "evaluation-plan candidates must be post-extraction plain C source"
            )
        expected_bundle = sha256_json(
            {
                "schema_version": "bpe.task-bundle.v1",
                "public_sha256": self.public_task_sha256,
                "private_sha256": self.private_grader_sha256,
            }
        )
        if self.task_bundle_sha256 != expected_bundle:
            raise ValueError("evaluation-plan task bundle digest is inconsistent")
        case_ids = [case.case_id for case in self.functional_cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("evaluation-plan functional case IDs must be unique")
        obligation_ids = [
            obligation.obligation_id for obligation in self.semantic_obligations
        ]
        if len(obligation_ids) != len(set(obligation_ids)):
            raise ValueError("evaluation-plan semantic obligation IDs must be unique")
        return self


def scoring_contract_for_plan(plan: EvaluationPlan) -> ScoringContract:
    """Derive the only scoring contract admitted for an evaluation plan."""

    object_checks = (
        ExpectedCheck(stage=Stage.OBJECT_POLICY, check_id="object/entrypoint"),
        ExpectedCheck(stage=Stage.OBJECT_POLICY, check_id="object/program-type"),
        ExpectedCheck(stage=Stage.OBJECT_POLICY, check_id="object/section"),
        ExpectedCheck(stage=Stage.OBJECT_POLICY, check_id="object/program-count"),
    )
    functional_checks = tuple(
        ExpectedCheck(
            stage=Stage.FUNCTIONAL,
            check_id=f"functional/{case.case_id}/{assertion.assertion_id}",
            required=assertion.required,
            weight=assertion.weight,
            input_artifacts={"input": case.input},
        )
        for case in plan.functional_cases
        for assertion in case.assertions
    )
    semantic_checks = tuple(
        ExpectedCheck(
            stage=Stage.SEMANTICS,
            check_id=f"semantics/{obligation.obligation_id}",
            required=obligation.required,
        )
        for obligation in plan.semantic_obligations
    )
    return ScoringContract(
        task_id=plan.task_id,
        task_version=plan.task_version,
        task_bundle_sha256=plan.task_bundle_sha256,
        checks=(*object_checks, *functional_checks, *semantic_checks),
    )


def build_evaluation_plan(bundle: TaskBundle) -> EvaluationPlan:
    """Project a loaded task into a pathname-free evaluator-side plan."""

    if (
        bundle.public.program.program_type != "xdp"
        or bundle.public.program.section != "xdp"
        or bundle.public.program.max_programs != 1
    ):
        raise JobBundleError("evaluation-plan v1 supports exactly one XDP program")
    unsupported_drivers = {
        case.driver
        for case in bundle.private.functional_cases
        if case.driver != "bpf_prog_run/xdp@1"
    }
    if unsupported_drivers:
        raise JobBundleError(
            "evaluation-plan v1 does not support task drivers: "
            + ", ".join(sorted(unsupported_drivers))
        )

    return EvaluationPlan(
        schema_version="bpe.evaluation-plan.v1",
        profile="xdp-bpf-prog-test-run-v1",
        task_id=bundle.public.task_id,
        task_version=bundle.public.version,
        family=bundle.public.family,
        public_task_sha256=bundle.public_sha256,
        private_grader_sha256=bundle.private_sha256,
        task_bundle_sha256=bundle.bundle_sha256,
        environment_id=bundle.public.environment_id,
        candidate_contract=bundle.public.candidate_contract.model_copy(
            update={"allow_markdown_fence": False}
        ),
        program=bundle.public.program,
        public_sdk_id=bundle.public.public_sdk_id,
        max_attempts=bundle.public.max_attempts,
        whole_attempt_timeout_seconds=bundle.public.whole_attempt_timeout_seconds,
        functional_cases=tuple(
            EvaluationFunctionalCase(
                case_id=case.case_id,
                input=ArtifactRef(
                    sha256=case.input_ref.sha256,
                    size_bytes=case.input_ref.size_bytes,
                    media_type="application/octet-stream",
                ),
                assertions=case.assertions,
            )
            for case in bundle.private.functional_cases
        ),
        semantic_obligations=bundle.private.semantic_obligations,
        strict_scoring_policy_id=bundle.private.strict_scoring_policy_id,
    )


def _physical_blob_table(references: tuple[ArtifactRef, ...]) -> tuple[JobBlobRef, ...]:
    by_digest: dict[str, int] = {}
    for reference in references:
        previous = by_digest.get(reference.sha256)
        if previous is not None and previous != reference.size_bytes:
            raise ValueError("one blob digest is paired with inconsistent sizes")
        by_digest[reference.sha256] = reference.size_bytes
    return tuple(
        JobBlobRef(sha256=digest, size_bytes=size)
        for digest, size in sorted(by_digest.items())
    )


class EvaluationJobManifest(_JobModel):
    """Canonical manifest for a prepared, explicitly non-dispatchable job."""

    schema_version: Literal["bpe.evaluation-job.v1"]
    status: Literal["prepared"]
    request: EvaluationRequest
    request_sha256: Sha256
    suite: SuiteManifest
    suite_sha256: Sha256
    experiment: ExperimentManifest
    experiment_sha256: Sha256
    environment: EnvironmentFingerprint
    environment_sha256: Sha256
    reward_policy: RewardPolicy
    reward_policy_sha256: Sha256
    harness_commit: _COMMIT
    expected_grader_id: Sha256
    restore_nonce: Sha256
    plan: EvaluationPlan
    plan_sha256: Sha256
    contract: ScoringContract
    contract_sha256: Sha256
    blobs: Annotated[tuple[JobBlobRef, ...], Field(min_length=1, max_length=MAX_JOB_BLOBS)]
    total_blob_bytes: Annotated[int, Field(ge=1, le=MAX_JOB_TOTAL_BLOB_BYTES)]
    execution_authorized: Literal[False]
    authoritative: Literal[False]

    @field_validator("blobs", mode="before")
    @classmethod
    def blobs_accept_a_json_array(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("execution_authorized", "authoritative", mode="before")
    @classmethod
    def false_claims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("prepared job bundles cannot authorize or claim execution")
        return value

    @model_validator(mode="after")
    def all_embedded_identities_are_cross_bound(self) -> Self:
        if self.environment.isolation != Isolation.MICROVM:
            raise ValueError("evaluation job preparation requires a microVM environment")
        if self.restore_nonce == "0" * 64:
            raise ValueError("restore nonce cannot use the all-zero placeholder")
        if self.request.environment_id != self.environment.environment_id:
            raise ValueError("job request and environment IDs differ")
        if self.plan.environment_id != self.environment.environment_id:
            raise ValueError("job plan and environment IDs differ")
        if (
            self.request.diagnostic_condition == "bpfix"
            and self.environment.bpfix_commit is None
        ):
            raise ValueError("bpfix evaluation jobs require a pinned bpfix commit")
        task_identity = (
            self.request.task_id,
            self.request.task_version,
            self.request.task_bundle_sha256,
        )
        if task_identity != (
            self.plan.task_id,
            self.plan.task_version,
            self.plan.task_bundle_sha256,
        ) or task_identity != (
            self.contract.task_id,
            self.contract.task_version,
            self.contract.task_bundle_sha256,
        ):
            raise ValueError("job request, plan, and scoring-contract task identities differ")
        if self.contract != scoring_contract_for_plan(self.plan):
            raise ValueError("job scoring contract is not exactly derived from its plan")
        if self.request.candidate.media_type != "text/x-c":
            raise ValueError("evaluation candidate must use the text/x-c media type")
        if self.request.candidate.size_bytes > self.plan.candidate_contract.max_response_bytes:
            raise ValueError("evaluation candidate exceeds the task candidate byte limit")

        digests = (
            (self.request_sha256, sha256_json(self.request), "request"),
            (self.suite_sha256, sha256_json(self.suite), "suite"),
            (self.experiment_sha256, sha256_json(self.experiment), "experiment"),
            (self.environment_sha256, sha256_json(self.environment), "environment"),
            (
                self.reward_policy_sha256,
                sha256_json(self.reward_policy),
                "reward policy",
            ),
            (self.plan_sha256, sha256_json(self.plan), "plan"),
            (self.contract_sha256, sha256_json(self.contract), "contract"),
        )
        for declared, actual, label in digests:
            if declared != actual:
                raise ValueError(f"job {label} digest does not match its embedded value")

        if (
            self.request.experiment_id != self.experiment.experiment_id
            or self.request.experiment_manifest_sha256 != self.experiment_sha256
        ):
            raise ValueError("job request does not bind the embedded experiment")
        if (
            self.request.suite_id != self.suite.suite_id
            or self.request.suite_manifest_sha256 != self.suite_sha256
            or self.experiment.suite_id != self.suite.suite_id
            or self.experiment.suite_manifest_sha256 != self.suite_sha256
        ):
            raise ValueError("job request and experiment do not bind the embedded suite")
        if (
            self.request.model_id != self.experiment.model_id
            or self.request.model_artifact_sha256
            != self.experiment.model_artifact_sha256
            or self.request.sampling_config_sha256
            != self.experiment.sampling_config_sha256
            or self.request.diagnostic_condition
            != self.experiment.diagnostic_condition
        ):
            raise ValueError("job request generation configuration differs from experiment")
        if (
            self.experiment.environment_sha256 != self.environment_sha256
            or self.suite.environment_id != self.environment.environment_id
        ):
            raise ValueError("job experiment or suite does not bind the environment")
        if (
            self.experiment.reward_policy_id != self.reward_policy.policy_id
            or self.experiment.reward_policy_sha256 != self.reward_policy_sha256
            or self.suite.strict_policy_id != self.plan.strict_scoring_policy_id
            or self.contract.strict_policy_id != self.suite.strict_policy_id
        ):
            raise ValueError("job reward or strict scoring policy identity differs")
        if (
            self.harness_commit != self.experiment.harness_commit
            or self.expected_grader_id != self.experiment.expected_grader_id
        ):
            raise ValueError("job harness or grader identity differs from experiment")
        if self.expected_grader_id != grader_id_for(
            self.request,
            self.environment,
            self.harness_commit,
        ):
            raise ValueError("job grader identity does not bind request and environment")

        seed_plans = {
            seed_plan.training_seed: seed_plan
            for seed_plan in self.experiment.seed_plans
        }
        seed_plan = seed_plans.get(self.request.training_seed)
        if seed_plan is None:
            raise ValueError("job request uses a training seed outside the experiment")
        if (
            self.request.checkpoint_id != seed_plan.checkpoint_id
            or self.request.checkpoint_artifact_sha256
            != seed_plan.checkpoint_artifact_sha256
        ):
            raise ValueError("job request checkpoint differs from its training seed plan")
        if self.request.sample_index >= len(seed_plan.generation_seeds):
            raise ValueError("job request sample index is outside the experiment")
        if (
            self.request.generation_seed
            != seed_plan.generation_seeds[self.request.sample_index]
        ):
            raise ValueError("job request generation seed differs from the experiment")
        if self.request.attempt_index >= self.plan.max_attempts:
            raise ValueError("job request attempt index exceeds the task limit")
        if (self.request.attempt_index == 0) != (
            self.request.parent_request_id is None
        ):
            raise ValueError("job request parent linkage does not match its attempt index")

        suite_tasks = [
            task for task in self.suite.tasks if task.task_id == self.request.task_id
        ]
        if len(suite_tasks) != 1:
            raise ValueError("job request task is not uniquely present in the suite")
        suite_task = suite_tasks[0]
        if (
            suite_task.task_version,
            suite_task.task_bundle_sha256,
            suite_task.evaluation_plan_sha256,
            suite_task.scoring_contract_sha256,
            suite_task.family,
            suite_task.program_type,
        ) != (
            self.plan.task_version,
            self.plan.task_bundle_sha256,
            self.plan_sha256,
            self.contract_sha256,
            self.plan.family,
            self.plan.program.program_type,
        ):
            raise ValueError("job task plan or contract differs from the frozen suite")

        required_references = (
            self.request.candidate,
            *(case.input for case in self.plan.functional_cases),
        )
        expected_blobs = _physical_blob_table(required_references)
        if self.blobs != expected_blobs:
            raise ValueError("job blob table must exactly cover candidate and functional inputs")
        expected_total = sum(blob.size_bytes for blob in expected_blobs)
        if self.total_blob_bytes != expected_total:
            raise ValueError("job total blob bytes do not match the exact blob table")
        return self


def build_evaluation_job_manifest(
    *,
    request: EvaluationRequest,
    suite: SuiteManifest,
    experiment: ExperimentManifest,
    environment: EnvironmentFingerprint,
    reward_policy: RewardPolicy,
    restore_nonce: str,
    plan: EvaluationPlan,
    contract: ScoringContract,
) -> EvaluationJobManifest:
    """Construct a fully cross-bound but explicitly non-dispatchable manifest."""

    blobs = _physical_blob_table(
        (request.candidate, *(case.input for case in plan.functional_cases))
    )
    return EvaluationJobManifest(
        schema_version="bpe.evaluation-job.v1",
        status="prepared",
        request=request,
        request_sha256=sha256_json(request),
        suite=suite,
        suite_sha256=sha256_json(suite),
        experiment=experiment,
        experiment_sha256=sha256_json(experiment),
        environment=environment,
        environment_sha256=sha256_json(environment),
        reward_policy=reward_policy,
        reward_policy_sha256=sha256_json(reward_policy),
        harness_commit=experiment.harness_commit,
        expected_grader_id=grader_id_for(
            request,
            environment,
            experiment.harness_commit,
        ),
        restore_nonce=restore_nonce,
        plan=plan,
        plan_sha256=sha256_json(plan),
        contract=contract,
        contract_sha256=sha256_json(contract),
        blobs=blobs,
        total_blob_bytes=sum(blob.size_bytes for blob in blobs),
        execution_authorized=False,
        authoritative=False,
    )


@dataclass(frozen=True)
class JobBundleReceipt:
    manifest: EvaluationJobManifest
    manifest_sha256: str


@dataclass(frozen=True)
class LoadedJobBlob:
    reference: JobBlobRef
    content: bytes


@dataclass(frozen=True)
class LoadedEvaluationJob:
    """A sealed in-memory view; consumers never reopen the source bundle paths."""

    manifest: EvaluationJobManifest
    manifest_sha256: str
    anchored: bool
    blobs: tuple[LoadedJobBlob, ...]

    def blob_bytes(self, digest: str) -> bytes:
        for blob in self.blobs:
            if blob.reference.sha256 == digest:
                return blob.content
        raise KeyError(digest)


def _atomic_write_at(parent_fd: int, name: str, content: bytes) -> None:
    nofollow, _, cloexec, _ = _required_open_flags()
    temp_name = f".{name}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short write while staging a job bundle")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(
            temp_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            os.unlink(temp_name, dir_fd=parent_fd)
        raise


def _required_open_flags() -> tuple[int, int, int, int]:
    names = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in names):
        raise JobBundleError("secure descriptor-relative bundle reads are unavailable")
    return os.O_NOFOLLOW, os.O_DIRECTORY, os.O_CLOEXEC, os.O_NONBLOCK


def _fstat_or_close(descriptor: int, *, label: str) -> os.stat_result:
    try:
        return os.fstat(descriptor)
    except OSError as exc:
        with suppress(OSError):
            os.close(descriptor)
        raise JobBundleError(f"cannot inspect opened {label}: {exc}") from exc


def _open_private_writer_parent(parent: Path) -> tuple[int, int, int]:
    """Open and retain the only pathname resolution boundary used by the writer."""

    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before = parent.lstat()
    except OSError as exc:
        raise JobBundleError(f"cannot inspect job bundle parent: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise JobBundleError(
            "job bundle writer requires a caller-owned, non-symlink parent "
            "with no group or other write permission"
        )
    try:
        descriptor = os.open(parent, os.O_RDONLY | nofollow | directory | cloexec)
    except OSError as exc:
        raise JobBundleError(f"cannot open job bundle parent: {exc}") from exc
    opened = _fstat_or_close(descriptor, label="job bundle parent")
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        os.close(descriptor)
        raise JobBundleError("job bundle parent changed while it was being opened")
    return descriptor, opened.st_dev, opened.st_ino


def _require_writer_parent_path(
    parent: Path,
    *,
    parent_fd: int,
    parent_device: int,
    parent_inode: int,
) -> None:
    """Fail if the caller-visible parent pathname no longer names the pinned directory."""

    try:
        visible = parent.lstat()
    except OSError as exc:
        raise JobBundleError(f"job bundle parent path changed: {exc}") from exc
    opened = os.fstat(parent_fd)
    expected = (parent_device, parent_inode)
    if (
        (visible.st_dev, visible.st_ino) != expected
        or (opened.st_dev, opened.st_ino) != expected
        or stat.S_ISLNK(visible.st_mode)
        or not stat.S_ISDIR(visible.st_mode)
    ):
        raise JobBundleError("job bundle parent path changed during preparation")


def _open_root(root: Path) -> tuple[int, int]:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before = root.lstat()
    except OSError as exc:
        raise JobBundleError(f"cannot inspect job bundle root: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise JobBundleError("job bundle root is not a non-symlink directory")
    try:
        descriptor = os.open(root, os.O_RDONLY | nofollow | directory | cloexec)
    except OSError as exc:
        raise JobBundleError(f"cannot open job bundle root: {exc}") from exc
    opened = _fstat_or_close(descriptor, label="job bundle root")
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or not stat.S_ISDIR(opened.st_mode)
    ):
        os.close(descriptor)
        raise JobBundleError("job bundle root changed while it was being opened")
    return descriptor, opened.st_dev


def _open_component(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    directory: bool,
    label: str,
) -> int:
    nofollow, directory_flag, cloexec, nonblock = _required_open_flags()
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise JobBundleError(f"cannot inspect {label}: {exc}") from exc
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        stat.S_ISLNK(before.st_mode)
        or not expected_kind(before.st_mode)
        or before.st_dev != root_device
    ):
        raise JobBundleError(f"{label} is not a same-device non-symlink object")
    if not directory and before.st_nlink != 1:
        raise JobBundleError(f"{label} must not be externally hard-linked")
    flags = os.O_RDONLY | nofollow | cloexec
    if directory:
        flags |= directory_flag
    else:
        # If a checked file is swapped for a FIFO before openat(), do not let the
        # verifier block before the post-open fstat rejects the replacement.
        flags |= nonblock
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise JobBundleError(f"cannot open {label}: {exc}") from exc
    opened = _fstat_or_close(descriptor, label=label)
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or not expected_kind(opened.st_mode)
        or opened.st_dev != root_device
        or (not directory and opened.st_nlink != 1)
    ):
        os.close(descriptor)
        raise JobBundleError(f"{label} changed while it was being opened")
    return descriptor


def _read_file_at(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    max_bytes: int,
    label: str,
    expected_bytes: int | None = None,
    component_opener: _ComponentOpener = _open_component,
) -> bytes:
    descriptor = component_opener(
        name,
        parent_fd=parent_fd,
        root_device=root_device,
        directory=False,
        label=label,
    )
    try:
        opened = os.fstat(descriptor)
        if opened.st_size > max_bytes:
            raise JobBundleError(f"{label} exceeds the {max_bytes}-byte limit")
        if expected_bytes is not None and opened.st_size != expected_bytes:
            raise JobBundleError(
                f"{label} size mismatch: expected {expected_bytes}, got {opened.st_size}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        if len(content) > max_bytes:
            raise JobBundleError(f"{label} exceeds the {max_bytes}-byte limit")
        if expected_bytes is not None and len(content) != expected_bytes:
            raise JobBundleError(
                f"{label} size mismatch: expected {expected_bytes}, got {len(content)}"
            )
        if len(content) != opened.st_size or (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
            opened.st_nlink,
        ):
            raise JobBundleError(f"{label} changed while it was being read")
        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _directory_entries(
    descriptor: int,
    *,
    label: str,
    max_entries: int,
) -> set[str]:
    entries: set[str] = set()
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                entries.add(entry.name)
                if len(entries) > max_entries:
                    raise JobBundleError(
                        f"{label} is not exactly closed: exceeds the "
                        f"{max_entries}-entry limit"
                    )
    except JobBundleError:
        raise
    except OSError as exc:
        raise JobBundleError(f"cannot enumerate {label}: {exc}") from exc
    if any(not isinstance(entry, str) for entry in entries):
        raise JobBundleError(f"{label} contains a non-text filename")
    return entries


def _validate_json_complexity(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_JOB_JSON_DEPTH or nodes > MAX_JOB_JSON_NODES:
            raise JobBundleError("job manifest JSON exceeds the structural complexity limit")
        if isinstance(current, dict):
            for key, child in current.items():
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise JobBundleError("job manifest keys must use Unicode scalar values")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise JobBundleError("job manifest strings must use Unicode scalar values")


def _parse_manifest(raw: bytes) -> EvaluationJobManifest:
    try:
        value = strict_json_loads(raw)
        _validate_json_complexity(value)
        manifest = EvaluationJobManifest.model_validate(value)
        canonical = canonical_json_bytes(manifest)
    except JobBundleError:
        raise
    except (CanonicalJSONError, ValidationError, ValueError) as exc:
        raise JobBundleError(f"invalid evaluation job manifest: {exc}") from exc
    if canonical != raw:
        raise JobBundleError("evaluation job manifest is not canonical JSON")
    return manifest


def _entry_exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise JobBundleError(f"cannot inspect job bundle target {name}: {exc}") from exc
    return True


def _create_staging_directory(
    *,
    parent_fd: int,
    parent_device: int,
) -> tuple[str, int]:
    for _ in range(128):
        name = f".bpe-job-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise JobBundleError(f"cannot create staged job bundle: {exc}") from exc
        descriptor = -1
        try:
            descriptor = _open_component(
                name,
                parent_fd=parent_fd,
                root_device=parent_device,
                directory=True,
                label="staged job bundle",
            )
            os.fchmod(descriptor, 0o700)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(OSError):
                os.rmdir(name, dir_fd=parent_fd)
            raise
        return name, descriptor
    raise JobBundleError("cannot allocate a unique staged job bundle name")


def _discard_staged_bundle(
    *,
    parent_fd: int,
    parent_device: int,
    staged_fd: int,
    staged_name: str,
    blob_names: tuple[str, ...],
) -> None:
    """Best-effort descriptor-relative cleanup of the writer-owned staging tree."""

    with suppress(OSError):
        os.unlink("manifest.json", dir_fd=staged_fd)
    blobs_fd = -1
    store_fd = -1
    try:
        try:
            blobs_fd = _open_component(
                "blobs",
                parent_fd=staged_fd,
                root_device=parent_device,
                directory=True,
                label="staged job blob-store parent",
            )
        except JobBundleError:
            blobs_fd = -1
        if blobs_fd >= 0:
            try:
                store_fd = _open_component(
                    "sha256",
                    parent_fd=blobs_fd,
                    root_device=parent_device,
                    directory=True,
                    label="staged job SHA-256 blob store",
                )
            except JobBundleError:
                store_fd = -1
        if store_fd >= 0:
            for name in blob_names:
                with suppress(OSError):
                    os.unlink(name, dir_fd=store_fd)
        if blobs_fd >= 0:
            with suppress(OSError):
                os.rmdir("sha256", dir_fd=blobs_fd)
            with suppress(OSError):
                os.rmdir("blobs", dir_fd=staged_fd)
    finally:
        if store_fd >= 0:
            os.close(store_fd)
        if blobs_fd >= 0:
            os.close(blobs_fd)
        with suppress(OSError):
            os.rmdir(staged_name, dir_fd=parent_fd)


def _publish_staged_bundle(
    *,
    parent_fd: int,
    parent_device: int,
    staged_fd: int,
    target_name: str,
    target_display: Path,
) -> int:
    """Reserve without replacement and publish relative to one pinned parent."""

    try:
        os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise JobBundleError(f"job bundle target already exists: {target_display}") from exc
    except OSError as exc:
        raise JobBundleError(
            f"cannot reserve job bundle target {target_display}: {exc}"
        ) from exc

    target_fd = _open_component(
        target_name,
        parent_fd=parent_fd,
        root_device=parent_device,
        directory=True,
        label="reserved job bundle target",
    )
    os.fchmod(target_fd, 0o700)
    try:
        os.rename(
            "blobs",
            "blobs",
            src_dir_fd=staged_fd,
            dst_dir_fd=target_fd,
        )
        # The manifest is the readiness marker.  A concurrent reader sees either an
        # invalid incomplete reservation or the complete closed tree, never a valid
        # manifest paired with a partially published blob store.
        os.rename(
            "manifest.json",
            "manifest.json",
            src_dir_fd=staged_fd,
            dst_dir_fd=target_fd,
        )
        os.fsync(target_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        os.close(target_fd)
        raise JobBundleError(
            "job bundle publication failed; the reserved target remains fail-closed: "
            f"{target_display}: {exc}"
        ) from exc
    return target_fd


def _load_evaluation_job_from_root(
    *,
    root_fd: int,
    root_device: int,
    expected_manifest_sha256: str | None = None,
    component_opener: _ComponentOpener = _open_component,
) -> LoadedEvaluationJob:
    """Load from a caller-owned, pinned root directory descriptor."""

    blobs_fd = -1
    sha256_fd = -1
    try:
        manifest_bytes = _read_file_at(
            "manifest.json",
            parent_fd=root_fd,
            root_device=root_device,
            max_bytes=MAX_JOB_MANIFEST_BYTES,
            label="job manifest",
            component_opener=component_opener,
        )
        manifest_sha256 = sha256_bytes(manifest_bytes)
        manifest = _parse_manifest(manifest_bytes)
        if (
            expected_manifest_sha256 is not None
            and manifest_sha256 != expected_manifest_sha256
        ):
            raise JobBundleError(
                "job manifest trust anchor mismatch: "
                f"expected {expected_manifest_sha256}, got {manifest_sha256}"
            )

        if _directory_entries(
            root_fd,
            label="job bundle root",
            max_entries=2,
        ) != {
            "manifest.json",
            "blobs",
        }:
            raise JobBundleError("job bundle root is not exactly closed")
        blobs_fd = component_opener(
            "blobs",
            parent_fd=root_fd,
            root_device=root_device,
            directory=True,
            label="job blob-store parent",
        )
        if _directory_entries(
            blobs_fd,
            label="job blob-store parent",
            max_entries=1,
        ) != {"sha256"}:
            raise JobBundleError("job blob-store parent is not exactly closed")
        sha256_fd = component_opener(
            "sha256",
            parent_fd=blobs_fd,
            root_device=root_device,
            directory=True,
            label="job SHA-256 blob store",
        )
        expected_names = {blob.sha256 for blob in manifest.blobs}
        if _directory_entries(
            sha256_fd,
            label="job SHA-256 blob store",
            max_entries=len(expected_names),
        ) != expected_names:
            raise JobBundleError("job SHA-256 blob store is not exactly closed")

        loaded: list[LoadedJobBlob] = []
        for reference in manifest.blobs:
            content = _read_file_at(
                reference.sha256,
                parent_fd=sha256_fd,
                root_device=root_device,
                max_bytes=MAX_JOB_BLOB_BYTES,
                expected_bytes=reference.size_bytes,
                label=f"job blob {reference.sha256}",
                component_opener=component_opener,
            )
            if sha256_bytes(content) != reference.sha256:
                raise JobBundleError(f"job blob digest mismatch: {reference.sha256}")
            loaded.append(LoadedJobBlob(reference=reference, content=content))

        loaded_by_digest = {
            blob.reference.sha256: blob.content for blob in loaded
        }
        candidate_bytes = loaded_by_digest[manifest.request.candidate.sha256]
        try:
            extracted = extract_c_source(
                candidate_bytes,
                max_bytes=manifest.plan.candidate_contract.max_response_bytes,
                allow_fence=False,
            )
        except SubmissionError as exc:
            raise JobBundleError(f"job candidate is not plain bounded C source: {exc}") from exc
        if extracted != candidate_bytes:
            raise JobBundleError("job candidate source changed during strict extraction")
        if sum(len(blob.content) for blob in loaded) != manifest.total_blob_bytes:
            raise JobBundleError("loaded job byte total differs from the manifest")

        # Re-enumerate the pinned directories after all reads.  Even if the source tree
        # changes immediately afterwards, consumers use only the sealed bytes above.
        if _directory_entries(
            root_fd,
            label="job bundle root",
            max_entries=2,
        ) != {
            "manifest.json",
            "blobs",
        } or _directory_entries(
            blobs_fd,
            label="job blob-store parent",
            max_entries=1,
        ) != {"sha256"}:
            raise JobBundleError("job bundle changed while it was being loaded")
        if _directory_entries(
            sha256_fd,
            label="job SHA-256 blob store",
            max_entries=len(expected_names),
        ) != expected_names:
            raise JobBundleError("job blob store changed while it was being loaded")

        return LoadedEvaluationJob(
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            anchored=expected_manifest_sha256 is not None,
            blobs=tuple(loaded),
        )
    finally:
        if sha256_fd >= 0:
            os.close(sha256_fd)
        if blobs_fd >= 0:
            os.close(blobs_fd)


def load_evaluation_job_bundle(
    bundle_dir: Path,
    *,
    expected_manifest_sha256: str | None = None,
) -> LoadedEvaluationJob:
    """Read one closed bundle into immutable bytes through pinned descriptors."""

    root_fd, root_device = _open_root(bundle_dir.absolute())
    try:
        return _load_evaluation_job_from_root(
            root_fd=root_fd,
            root_device=root_device,
            expected_manifest_sha256=expected_manifest_sha256,
        )
    finally:
        os.close(root_fd)


def write_evaluation_job_bundle(
    bundle_dir: Path,
    *,
    manifest: EvaluationJobManifest,
    blobs: Mapping[str, bytes],
) -> JobBundleReceipt:
    """Stage, self-verify, and publish a new prepared evaluation bundle."""

    try:
        manifest = EvaluationJobManifest.model_validate(manifest.model_dump(mode="python"))
        manifest_bytes = canonical_json_bytes(manifest)
    except (CanonicalJSONError, ValidationError, ValueError) as exc:
        raise JobBundleError(f"invalid evaluation job manifest: {exc}") from exc
    if len(manifest_bytes) > MAX_JOB_MANIFEST_BYTES:
        raise JobBundleError(
            f"job manifest exceeds the {MAX_JOB_MANIFEST_BYTES}-byte limit"
        )

    try:
        supplied_items = tuple(islice(iter(blobs.items()), MAX_JOB_BLOBS + 1))
    except Exception as exc:
        raise JobBundleError(f"cannot snapshot supplied job blobs: {exc}") from exc
    if len(supplied_items) > MAX_JOB_BLOBS:
        raise JobBundleError(f"supplied job blobs exceed the {MAX_JOB_BLOBS}-blob limit")
    supplied: dict[str, bytes] = {}
    for item in supplied_items:
        try:
            digest, content = item
        except (TypeError, ValueError) as exc:
            raise JobBundleError("supplied job blob entries must be key/value pairs") from exc
        if type(digest) is not str:
            raise JobBundleError("supplied job blob keys must be plain strings")
        if digest in supplied:
            raise JobBundleError(f"supplied job blob key is duplicated: {digest}")
        if type(content) is not bytes:
            raise JobBundleError(f"job blob {digest} must be immutable bytes")
        supplied[digest] = content

    expected = {reference.sha256: reference for reference in manifest.blobs}
    if set(supplied) != set(expected):
        raise JobBundleError("supplied blob keys do not exactly match the job manifest")
    for digest, content in supplied.items():
        reference = expected[digest]
        if len(content) != reference.size_bytes or sha256_bytes(content) != digest:
            raise JobBundleError(f"job blob content does not match its identity: {digest}")

    unresolved = bundle_dir.absolute()
    target_name = unresolved.name
    if target_name in {"", ".", ".."}:
        raise JobBundleError("job bundle target must name one directory entry")
    unresolved.parent.mkdir(parents=True, exist_ok=True)

    parent_fd = -1
    parent_device = -1
    parent_inode = -1
    staged_name: str | None = None
    staged_fd = -1
    blobs_fd = -1
    store_fd = -1
    target_fd = -1
    try:
        parent_fd, parent_device, parent_inode = _open_private_writer_parent(
            unresolved.parent
        )
        if _entry_exists_at(parent_fd, target_name):
            raise JobBundleError(f"job bundle target already exists: {unresolved}")
        staged_name, staged_fd = _create_staging_directory(
            parent_fd=parent_fd,
            parent_device=parent_device,
        )
        os.mkdir("blobs", mode=0o700, dir_fd=staged_fd)
        blobs_fd = _open_component(
            "blobs",
            parent_fd=staged_fd,
            root_device=parent_device,
            directory=True,
            label="staged job blob-store parent",
        )
        os.fchmod(blobs_fd, 0o700)
        os.mkdir("sha256", mode=0o700, dir_fd=blobs_fd)
        store_fd = _open_component(
            "sha256",
            parent_fd=blobs_fd,
            root_device=parent_device,
            directory=True,
            label="staged job SHA-256 blob store",
        )
        os.fchmod(store_fd, 0o700)
        for reference in manifest.blobs:
            _atomic_write_at(
                store_fd,
                reference.sha256,
                supplied[reference.sha256],
            )
        _atomic_write_at(staged_fd, "manifest.json", manifest_bytes)
        os.fsync(store_fd)
        os.fsync(blobs_fd)
        os.fsync(staged_fd)
        os.close(store_fd)
        store_fd = -1
        os.close(blobs_fd)
        blobs_fd = -1

        manifest_sha256 = sha256_bytes(manifest_bytes)
        loaded = _load_evaluation_job_from_root(
            root_fd=staged_fd,
            root_device=parent_device,
            expected_manifest_sha256=manifest_sha256,
        )
        if loaded.manifest != manifest:
            raise JobBundleError("self-verified job manifest differs from the staged value")
        _require_writer_parent_path(
            unresolved.parent,
            parent_fd=parent_fd,
            parent_device=parent_device,
            parent_inode=parent_inode,
        )
        target_fd = _publish_staged_bundle(
            parent_fd=parent_fd,
            parent_device=parent_device,
            staged_fd=staged_fd,
            target_name=target_name,
            target_display=unresolved,
        )
        published = _load_evaluation_job_from_root(
            root_fd=target_fd,
            root_device=parent_device,
            expected_manifest_sha256=manifest_sha256,
        )
        if published.manifest != manifest:
            raise JobBundleError("published job manifest differs from the staged value")
        _require_writer_parent_path(
            unresolved.parent,
            parent_fd=parent_fd,
            parent_device=parent_device,
            parent_inode=parent_inode,
        )
        os.rmdir(staged_name, dir_fd=parent_fd)
        staged_name = None
        return JobBundleReceipt(manifest=manifest, manifest_sha256=manifest_sha256)
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if store_fd >= 0:
            os.close(store_fd)
        if blobs_fd >= 0:
            os.close(blobs_fd)
        if staged_name is not None and staged_fd >= 0 and parent_fd >= 0:
            _discard_staged_bundle(
                parent_fd=parent_fd,
                parent_device=parent_device,
                staged_fd=staged_fd,
                staged_name=staged_name,
                blob_names=tuple(supplied),
            )
        if staged_fd >= 0:
            os.close(staged_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


__all__ = [
    "MAX_JOB_BLOBS",
    "MAX_JOB_BLOB_BYTES",
    "MAX_JOB_JSON_DEPTH",
    "MAX_JOB_JSON_NODES",
    "MAX_JOB_MANIFEST_BYTES",
    "MAX_JOB_TOTAL_BLOB_BYTES",
    "EvaluationFunctionalCase",
    "EvaluationJobManifest",
    "EvaluationPlan",
    "JobBlobRef",
    "JobBundleError",
    "JobBundleReceipt",
    "LoadedEvaluationJob",
    "LoadedJobBlob",
    "build_evaluation_job_manifest",
    "build_evaluation_plan",
    "load_evaluation_job_bundle",
    "scoring_contract_for_plan",
    "write_evaluation_job_bundle",
]
