"""Strict replay contract for native inert-launcher qualification evidence.

This module is deliberately process-free.  It validates a self-contained, unsigned
report emitted by the evaluator-only privileged probe, reconstructs every raw native
socket record, and replays accepted transcripts through ``inert_native_protocol``.
The report is local qualification evidence only: it grants no launch, grading, or
execution authority and makes no durability or authenticity claim.  JSON Schema
validation alone is insufficient; callers must use the semantic replay validators in
this module.  In particular, the emergency case records a cleanup outcome under the
fixed launcher and trusted-kernel assumptions; its transcript does not independently
prove that a ``cgroup.kill`` write succeeded.
"""

from __future__ import annotations

from collections.abc import Mapping
from struct import Struct
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from bpe.canonical import canonical_json_bytes, sha256_bytes, strict_json_loads
from bpe.inert_artifact import (
    FIXED_SECCOMP_POLICY_ID,
    FIXED_SECCOMP_POLICY_SHA256,
    MAX_LAUNCHER_ARTIFACT_BYTES,
    REQUIRED_EXEC_SEALS,
    SEALED_EXECUTABLE_MODE,
    LinuxInertLauncherArtifactPreflightReceipt,
)
from bpe.inert_native_protocol import (
    ACHIEVED_RESULT_MASK,
    LINUX_MAX_PID,
    PROTOCOL_MAX_ERRNO,
    PROTOCOL_MAX_FRAMES,
    InertNativeProtocolViolation,
    InertNativeSocketRecord,
    InertNativeTranscript,
    NativeExitCode,
    parse_inert_native_transcript,
)
from bpe.models import Sha256, StableId

NATIVE_QUALIFICATION_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-qualification\x00v1\x00"
)
NATIVE_QUALIFICATION_CASE_SET_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-case-set\x00v1\x00"
)
NATIVE_QUALIFICATION_SOURCE_MANIFEST_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-source-manifest\x00v1\x00"
)
NATIVE_QUALIFICATION_INVOCATION_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-invocation\x00v1\x00"
)
NATIVE_QUALIFICATION_TRANSCRIPT_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-transcript\x00v1\x00"
)
NATIVE_QUALIFICATION_CONTEXT_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-context\x00v1\x00"
)
NATIVE_QUALIFICATION_RUNTIME_DEPENDENCY_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-runtime-dependencies\x00v1\x00"
)
NATIVE_QUALIFICATION_OUTER_SECCOMP_DOMAIN = (
    b"BPE\x00linux-inert-launcher-native-outer-seccomp\x00v1\x00"
)

NativeQualificationCaseName = Literal[
    "success",
    "extra-fd",
    "inbound",
    "peer-close",
    "emergency-cgroup-kill",
]
NATIVE_QUALIFICATION_CASES: tuple[NativeQualificationCaseName, ...] = (
    "success",
    "extra-fd",
    "inbound",
    "peer-close",
    "emergency-cgroup-kill",
)
NATIVE_QUALIFICATION_CASE_SET_ID = "bpe.linux-inert-launcher-native-case-set.v1"
NATIVE_QUALIFICATION_PARSER_ID = "bpe.inert-native-transcript-parser.v1"
NATIVE_QUALIFICATION_LAUNCHER_PROTOCOL_ID = (
    "bpe.clone3-inert-launcher-protocol.v1"
)
MAX_NATIVE_QUALIFICATION_REPORT_BYTES = 128 * 1024
MAX_NATIVE_QUALIFICATION_PROVENANCE_BYTES = 64 * 1024
MAX_NATIVE_QUALIFICATION_TRACKED_TREE_MANIFEST_BYTES = 128 * 1024
MAX_NATIVE_QUALIFICATION_TRACKED_TREE_FILES = 10_000
MAX_NATIVE_QUALIFICATION_TRACKED_TREE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_NATIVE_QUALIFICATION_SOURCE_TOTAL_BYTES = 16 * 1024 * 1024
MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS = 512
MAX_NATIVE_QUALIFICATION_RUNTIME_FILES = 100_000
MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_NATIVE_QUALIFICATION_BUILT_WHEEL_BYTES = 64 * 1024 * 1024
NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION = "0.1.0"
NATIVE_QUALIFICATION_BUILT_WHEEL_FILENAME = (
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}-py3-none-any.whl"
)
NATIVE_QUALIFICATION_BUILT_WHEEL_PATH = (
    f"/dist/{NATIVE_QUALIFICATION_BUILT_WHEEL_FILENAME}"
)

NATIVE_QUALIFICATION_BPE_SOURCE_PATHS = (
    "src/bpe/__init__.py",
    "src/bpe/admission.py",
    "src/bpe/aggregate.py",
    "src/bpe/canonical.py",
    "src/bpe/capabilities.py",
    "src/bpe/cgroup.py",
    "src/bpe/cli.py",
    "src/bpe/corpus.py",
    "src/bpe/data/corpus-audit-v1.json",
    "src/bpe/data/reward-v1.json",
    "src/bpe/dispatch.py",
    "src/bpe/grading.py",
    "src/bpe/identity.py",
    "src/bpe/inert_artifact.py",
    "src/bpe/inert_fixture.py",
    "src/bpe/inert_launch.py",
    "src/bpe/inert_native_protocol.py",
    "src/bpe/inert_native_qualification.py",
    "src/bpe/ingress.py",
    "src/bpe/job.py",
    "src/bpe/models.py",
    "src/bpe/oracle.py",
    "src/bpe/qualification.py",
    "src/bpe/replay.py",
    "src/bpe/schemas.py",
    "src/bpe/submission.py",
    "src/bpe/task.py",
    "src/bpe/worker_cli.py",
    "src/bpe/worker_protocol.py",
)

NATIVE_QUALIFICATION_WHEEL_DIST_INFO_PATHS = (
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/METADATA",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/RECORD",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/WHEEL",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/entry_points.txt",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/licenses/LICENSE",
)
NATIVE_QUALIFICATION_RUNTIME_INSTALLER_PATHS = (
    "bin/bpe",
    "bin/bpe-worker",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/INSTALLER",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/REQUESTED",
    f"bpe-{NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION}.dist-info/direct_url.json",
)

NATIVE_QUALIFICATION_SOURCE_PATHS = (
    ".github/workflows/native-qualification.yml",
    ".github/workflows/ci.yml",
    "scripts/validate_repository_projection.py",
    "tests/integration/inert_fixture_launcher_native_probe.py",
    "tests/integration/cgroup_v2_native_probe.py",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "worker/linux/inert_fixture_launcher/launcher.c",
    "worker/linux/inert_fixture_launcher/protocol.h",
    "schemas/linux-inert-launcher-native-qualification-report-v1.json",
    "uv.lock",
    "worker/linux/inert_fixture_launcher/Makefile",
    "worker/linux/inert_fixture_launcher/descriptor_scan_test.c",
    "worker/linux/inert_fixture_launcher/protocol_golden_test.c",
    "worker/linux/inert_fixture_launcher/seccomp_filter.h",
    "worker/linux/inert_fixture_launcher/seccomp_policy.h",
    "worker/linux/inert_fixture_launcher/seccomp_policy_digest.h",
    "worker/linux/inert_fixture_launcher/seccomp_policy_dump.c",
    "worker/linux/inert_fixture_launcher/wire.h",
    "scripts/export_schemas.py",
    *NATIVE_QUALIFICATION_BPE_SOURCE_PATHS,
)

NATIVE_QUALIFICATION_FAULT_PROFILE_ID = (
    "bpe.native-qualification.pidfd-send-signal-eperm.v1"
)
NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTIONS = (
    (0x20, 0, 0, 4),
    (0x15, 1, 0, 0xC000003E),
    (0x06, 0, 0, 0x80000000),
    (0x20, 0, 0, 0),
    (0x35, 0, 1, 0x40000000),
    (0x06, 0, 0, 0x80000000),
    (0x15, 0, 1, 424),
    (0x06, 0, 0, 0x00050001),
    (0x06, 0, 0, 0x7FFF0000),
)
_SECCOMP_INSTRUCTION_WIRE = Struct(">HBBI")
NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTION_BYTES = b"".join(
    _SECCOMP_INSTRUCTION_WIRE.pack(code, jump_true, jump_false, value)
    for code, jump_true, jump_false, value in (
        NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTIONS
    )
)
NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256 = sha256_bytes(
    NATIVE_QUALIFICATION_OUTER_SECCOMP_DOMAIN
    + NATIVE_QUALIFICATION_FAULT_PROFILE_ID.encode("ascii")
    + b"\x00"
    + NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTION_BYTES
)

_GIT_COMMIT = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
_SHA1 = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
_FRAME_HEX = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
_PID = Annotated[int, Field(ge=1, le=LINUX_MAX_PID)]
_BOUNDED_TEXT = Annotated[str, Field(min_length=1, max_length=512)]
_VERSION_TEXT = Annotated[str, Field(min_length=1, max_length=1024)]
NativeQualificationActorCategory = Literal["unverified"]


class LinuxInertLauncherNativeQualificationError(ValueError):
    """A bounded failure from strict native-qualification replay validation."""


class _QualificationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        strict=True,
    )


class NativeQualificationUpstreamWorkflowRun(_QualificationModel):
    """Exact successful CI run whose commit the trusted controller qualifies."""

    workflow_name: Literal["CI"]
    workflow_id: Annotated[int, Field(ge=1)]
    workflow_path: Literal[".github/workflows/ci.yml"]
    run_id: Annotated[int, Field(ge=1)]
    run_attempt: Annotated[int, Field(ge=1, le=1000)]
    event: Literal["push"]
    head_branch: Literal["main"]
    head_repository_full_name: Literal["synechism/bpe"]
    head_sha: _GIT_COMMIT
    conclusion: Literal["success"]


class NativeQualificationContextBinding(_QualificationModel):
    """Exact cross-layer inputs covered by the native qualification context digest."""

    git_commit: _GIT_COMMIT
    source_manifest_sha256: Sha256
    tracked_tree_content_manifest_sha256: Sha256
    tracked_tree_matches_git_commit: Literal[True]
    built_wheel_sha256: Sha256
    runtime_dependency_manifest_sha256: Sha256
    runtime_root_tree_sha256: Sha256
    runtime_root_total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES),
    ]
    runtime_root_tree_completeness_method: Literal[
        "recursive-lstat-exact-wheel-projection-v1"
    ]
    launcher_sha256: Sha256
    workflow_sha256: Sha256
    github_repository: Literal["synechism/bpe"]
    github_sha: _GIT_COMMIT
    github_run_id: Annotated[int, Field(ge=1)]
    github_run_attempt: Annotated[int, Field(ge=1, le=1000)]
    github_job: Literal["native-qualification"]
    github_event: Literal["workflow_run"]
    github_ref: Literal["refs/heads/main"]
    github_actor_category: NativeQualificationActorCategory
    upstream_workflow_run: NativeQualificationUpstreamWorkflowRun
    container_invocation_sha256: Sha256

    @field_validator("tracked_tree_matches_git_commit", mode="before")
    @classmethod
    def tracked_tree_must_match_commit(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification tracked tree does not match the commit")
        return value

    @model_validator(mode="after")
    def controller_and_upstream_commit_are_exact(self) -> Self:
        if not (
            self.git_commit
            == self.github_sha
            == self.upstream_workflow_run.head_sha
        ):
            raise ValueError(
                "native qualification controller and upstream commits differ"
            )
        return self


class NativeQualificationSourceFile(_QualificationModel):
    path: Annotated[str, Field(min_length=1, max_length=256)]
    sha256: Sha256
    size_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES),
    ]


class NativeQualificationSourceManifest(_QualificationModel):
    schema_version: Literal["bpe.linux-inert-launcher-native-source-manifest.v1"]
    manifest_sha256: Sha256
    files: Annotated[
        tuple[NativeQualificationSourceFile, ...],
        Field(
            min_length=len(NATIVE_QUALIFICATION_SOURCE_PATHS),
            max_length=len(NATIVE_QUALIFICATION_SOURCE_PATHS),
        ),
    ]

    @field_validator("files", mode="before")
    @classmethod
    def file_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def paths_and_digest_are_exact(self) -> Self:
        if tuple(item.path for item in self.files) != NATIVE_QUALIFICATION_SOURCE_PATHS:
            raise ValueError("native qualification source manifest has the wrong file set")
        expected = sha256_bytes(
            NATIVE_QUALIFICATION_SOURCE_MANIFEST_DOMAIN
            + canonical_json_bytes(
                self.model_dump(mode="python", exclude={"manifest_sha256"})
            )
        )
        if self.manifest_sha256 != expected:
            raise ValueError("native qualification source manifest digest is inconsistent")
        return self


def native_qualification_commit_bpe_tree_manifest_sha256(
    source_manifest: NativeQualificationSourceManifest,
) -> str:
    """Map the complete committed ``src/bpe`` tree to its installed wheel paths."""

    validated = NativeQualificationSourceManifest.model_validate(
        source_manifest,
        strict=True,
    )
    by_path = {item.path: item for item in validated.files}
    files = []
    for source_path in NATIVE_QUALIFICATION_BPE_SOURCE_PATHS:
        item = by_path[source_path]
        files.append(
            {
                "path": source_path.removeprefix("src/"),
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
        )
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "bpe.python-installed-tree-content-manifest.v1",
                "files": files,
            }
        )
    )


class NativeQualificationSourceRun(_QualificationModel):
    repository: Literal["github.com/synechism/bpe"]
    git_commit: _GIT_COMMIT
    github_context_file_sha256: Sha256
    github_context_file_size_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_PROVENANCE_BYTES),
    ]
    source_manifest: NativeQualificationSourceManifest
    source_manifest_total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_SOURCE_TOTAL_BYTES),
    ]
    tracked_tree_manifest_method: Literal[
        "git-commit-blob-canonical-content-manifest-v1"
    ]
    tracked_tree_content_manifest_sha256: Sha256
    tracked_tree_manifest_file_size_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_TRACKED_TREE_MANIFEST_BYTES),
    ]
    tracked_tree_total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_TRACKED_TREE_TOTAL_BYTES),
    ]
    tracked_tree_matches_git_commit: Literal[True]
    commit_bpe_tree_manifest_method: Literal[
        "git-src-bpe-to-installed-bpe-tree-content-manifest-v1"
    ]
    commit_bpe_tree_manifest_sha256: Sha256
    built_wheel_bpe_tree_manifest_method: Literal[
        "closed-wheel-bpe-tree-content-manifest-v1"
    ]
    built_wheel_bpe_tree_manifest_sha256: Sha256
    built_wheel_size_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_BUILT_WHEEL_BYTES),
    ]
    probe_source_size_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES),
    ]
    workflow_path: Literal[".github/workflows/native-qualification.yml"]
    workflow_sha256: Sha256
    github_repository: Literal["synechism/bpe"]
    github_sha: _GIT_COMMIT
    github_run_id: Annotated[int, Field(ge=1)]
    github_run_attempt: Annotated[int, Field(ge=1, le=1000)]
    github_job: Literal["native-qualification"]
    github_event: Literal["workflow_run"]
    github_ref: Literal["refs/heads/main"]
    github_actor_category: NativeQualificationActorCategory
    upstream_workflow_run: NativeQualificationUpstreamWorkflowRun
    context_source: Literal["github-actions-workflow-run-environment-v1"]
    ci_context_authenticated: Literal[False]
    built_wheel_sha256: Sha256

    @field_validator("tracked_tree_matches_git_commit", mode="before")
    @classmethod
    def tracked_tree_must_match_commit(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification tracked tree does not match the commit")
        return value

    @field_validator("ci_context_authenticated", mode="before")
    @classmethod
    def ci_context_must_remain_unauthenticated(cls, value: object) -> object:
        if value is not False:
            raise ValueError("native qualification CI context is not authenticated")
        return value

    @model_validator(mode="after")
    def workflow_binding_is_exact(self) -> Self:
        source_by_path = {item.path: item for item in self.source_manifest.files}
        manifest_total_bytes = sum(item.size_bytes for item in self.source_manifest.files)
        probe = source_by_path[
            "tests/integration/inert_fixture_launcher_native_probe.py"
        ]
        if (
            self.tracked_tree_total_bytes < self.source_manifest_total_bytes
            or self.source_manifest_total_bytes != manifest_total_bytes
            or self.probe_source_size_bytes != probe.size_bytes
        ):
            raise ValueError(
                "native qualification source byte totals are inconsistent"
            )
        if self.commit_bpe_tree_manifest_sha256 != (
            native_qualification_commit_bpe_tree_manifest_sha256(self.source_manifest)
        ):
            raise ValueError("native qualification committed BPE tree is inconsistent")
        workflow = self.source_manifest.files[0]
        if workflow.path != self.workflow_path or workflow.sha256 != self.workflow_sha256:
            raise ValueError("native qualification workflow binding is inconsistent")
        upstream_workflow = self.source_manifest.files[1]
        if upstream_workflow.path != self.upstream_workflow_run.workflow_path:
            raise ValueError("native qualification upstream workflow binding is inconsistent")
        if not (
            self.git_commit
            == self.github_sha
            == self.upstream_workflow_run.head_sha
        ):
            raise ValueError(
                "native qualification controller and upstream commits differ"
            )
        return self


class NativeQualificationNamespaceIdentity(_QualificationModel):
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=1)]


class NativeQualificationHost(_QualificationModel):
    runner_architecture: Literal["x86_64"]
    docker_server_architecture: Literal["x86_64"]
    container_architecture: Literal["x86_64"]
    emulation_detected: Literal[False]
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    kernel_version: _VERSION_TEXT
    proc_version_sha256: Sha256
    boot_id_sha256: Sha256
    base_page_size_bytes: Literal[4096]
    cgroup_v2_filesystem_magic: Literal[0x63677270]
    pid_namespace: NativeQualificationNamespaceIdentity
    mount_namespace: NativeQualificationNamespaceIdentity
    user_namespace: NativeQualificationNamespaceIdentity
    cgroup_namespace: NativeQualificationNamespaceIdentity

    @field_validator("emulation_detected", mode="before")
    @classmethod
    def emulation_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("native qualification cannot accept emulated execution")
        return value


NativeQualificationMountPurpose = Literal[
    "provenance-context",
    "tracked-tree-manifest",
    "built-wheel",
    "probe",
    "launcher",
    "dependency-tree",
    "source-tree",
    "qualification-output",
]
_MOUNT_CONTRACTS: dict[
    NativeQualificationMountPurpose,
    tuple[str, Literal["file", "directory"], bool, int],
] = {
    "provenance-context": (
        "/qualification-provenance/context.json",
        "file",
        True,
        0o444,
    ),
    "tracked-tree-manifest": (
        "/qualification-provenance/tracked-tree-content-manifest.json",
        "file",
        True,
        0o444,
    ),
    "built-wheel": (NATIVE_QUALIFICATION_BUILT_WHEEL_PATH, "file", True, 0o444),
    "probe": ("/probe.py", "file", True, 0o444),
    "launcher": ("/launcher", "file", True, 0o555),
    "dependency-tree": ("/dependencies", "directory", True, 0o555),
    "source-tree": ("/qualification-source", "directory", True, 0o555),
    "qualification-output": (
        "/qualification-output",
        "directory",
        False,
        0o700,
    ),
}
_MOUNT_PURPOSES: tuple[NativeQualificationMountPurpose, ...] = tuple(
    _MOUNT_CONTRACTS
)


class NativeQualificationMountBinding(_QualificationModel):
    purpose: NativeQualificationMountPurpose
    target_path: Annotated[str, Field(min_length=1, max_length=256)]
    target_kind: Literal["file", "directory"]
    source_sha256: Sha256 | None
    source_size_bytes: Annotated[
        int,
        Field(ge=0, le=MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES),
    ] | None
    readonly: bool
    target_mode: Annotated[int, Field(ge=0, le=0o7777)]

    @model_validator(mode="after")
    def fixed_mount_contract_is_exact(self) -> Self:
        target_path, target_kind, readonly, target_mode = _MOUNT_CONTRACTS[
            self.purpose
        ]
        if (
            self.target_path != target_path
            or self.target_kind != target_kind
            or self.readonly is not readonly
            or self.target_mode != target_mode
        ):
            raise ValueError("native qualification mount contract is inconsistent")
        if self.purpose == "qualification-output":
            if self.source_sha256 is not None or self.source_size_bytes is not None:
                raise ValueError("native qualification output mount has source evidence")
        elif self.source_sha256 is None or self.source_size_bytes is None:
            raise ValueError("native qualification input mount lacks source evidence")
        return self


class NativeQualificationContainerInvocation(_QualificationModel):
    schema_version: Literal["bpe.linux-inert-launcher-native-invocation.v1"]
    invocation_sha256: Sha256
    image_reference: Annotated[
        str,
        Field(pattern=r"^[^@\s]+@sha256:[0-9a-f]{64}$", max_length=512),
    ]
    image_manifest_sha256: Sha256
    image_platform_sha256: Sha256
    image_config_sha256: Sha256
    platform: Literal["linux/amd64"]
    command_contract: Literal["python-no-site-pid1-sealed-fd-exec-v1"]
    privileged_configured: Literal[True]
    pid_namespace_mode: Literal["container-default-private"]
    mount_namespace_mode: Literal["container-default-private"]
    user_namespace_mode: Literal["daemon-default-recorded-only"]
    cgroup_namespace_mode: Literal["private"]
    network_mode: Literal["none"]
    mount_bindings: Annotated[
        tuple[NativeQualificationMountBinding, ...],
        Field(min_length=len(_MOUNT_PURPOSES), max_length=len(_MOUNT_PURPOSES)),
    ]
    distribution_mount_readonly: Literal[True]
    launcher_mount_readonly: Literal[True]
    probe_mount_readonly: Literal[True]
    dependencies_mount_readonly: Literal[True]
    qualification_output_mount: Literal["dedicated-readwrite-output-v1"]
    qualification_output_mount_readwrite: Literal[True]

    @field_validator("mount_bindings", mode="before")
    @classmethod
    def mount_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator(
        "privileged_configured",
        "distribution_mount_readonly",
        "launcher_mount_readonly",
        "probe_mount_readonly",
        "dependencies_mount_readonly",
        "qualification_output_mount_readwrite",
        mode="before",
    )
    @classmethod
    def invocation_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification invocation contract is not exact")
        return value

    @model_validator(mode="after")
    def image_and_invocation_digest_are_exact(self) -> Self:
        if not self.image_reference.endswith(self.image_manifest_sha256):
            raise ValueError("native qualification image reference digest is inconsistent")
        expected = sha256_bytes(
            NATIVE_QUALIFICATION_INVOCATION_DOMAIN
            + canonical_json_bytes(
                self.model_dump(mode="python", exclude={"invocation_sha256"})
            )
        )
        if self.invocation_sha256 != expected:
            raise ValueError("native qualification invocation digest is inconsistent")
        if tuple(binding.purpose for binding in self.mount_bindings) != _MOUNT_PURPOSES:
            raise ValueError("native qualification invocation has the wrong mount set")
        return self


class NativeQualificationRuntimeDistribution(_QualificationModel):
    root: Literal["runtime", "dependencies"]
    normalized_name: Annotated[
        str,
        Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", min_length=1, max_length=128),
    ]
    version: Annotated[str, Field(min_length=1, max_length=128)]
    aggregate_scope: Literal["package-tree", "distribution-files"]
    file_count: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_RUNTIME_FILES),
    ]
    total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES),
    ]
    aggregate_tree_sha256: Sha256


def native_qualification_runtime_dependency_manifest_sha256(
    distributions: tuple[NativeQualificationRuntimeDistribution, ...],
) -> str:
    """Digest the exact ordered, bounded runtime-distribution summaries."""

    if (
        type(distributions) is not tuple
        or not 1 <= len(distributions) <= MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS
    ):
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification runtime distributions have the wrong shape"
        )
    try:
        validated = tuple(
            NativeQualificationRuntimeDistribution.model_validate(item, strict=True)
            for item in distributions
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification runtime distributions are invalid"
        ) from exc
    identities = tuple(
        (item.root, item.normalized_name, item.version) for item in validated
    )
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(
        identities
    ):
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification runtime distributions are not canonical"
        )
    return sha256_bytes(
        NATIVE_QUALIFICATION_RUNTIME_DEPENDENCY_DOMAIN
        + canonical_json_bytes(
            {
                "schema_version": (
                    "bpe.linux-inert-launcher-native-runtime-dependencies.v1"
                ),
                "distributions": [
                    item.model_dump(mode="python") for item in validated
                ],
            }
        )
    )


class NativeQualificationContainer(_QualificationModel):
    invocation: NativeQualificationContainerInvocation
    docker_server_version: _BOUNDED_TEXT
    runtime_name: _BOUNDED_TEXT
    runtime_version: _BOUNDED_TEXT
    runtime_id: _BOUNDED_TEXT
    runtime_dependency_manifest_method: Literal[
        "python-distribution-summary-tree-digest-v1"
    ]
    runtime_dependency_manifest_sha256: Sha256
    runtime_distributions: Annotated[
        tuple[NativeQualificationRuntimeDistribution, ...],
        Field(
            min_length=1,
            max_length=MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS,
        ),
    ]
    dependency_root_tree_manifest_method: Literal[
        "canonical-relative-path-content-manifest-v1"
    ]
    dependency_root_tree_sha256: Sha256
    dependency_root_total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES),
    ]
    runtime_distribution_wheel_sha256: Sha256
    runtime_bpe_tree_manifest_method: Literal[
        "installed-bpe-tree-content-manifest-v1"
    ]
    runtime_bpe_tree_manifest_sha256: Sha256
    runtime_bpe_tree_matches_built_wheel: Literal[True]
    runtime_root_tree_manifest_method: Literal[
        "canonical-relative-path-content-manifest-v1"
    ]
    runtime_root_tree_completeness_method: Literal[
        "recursive-lstat-exact-wheel-projection-v1"
    ]
    runtime_root_tree_sha256: Sha256
    runtime_root_total_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES),
    ]
    runtime_probe_source_sha256: Sha256
    runtime_lockfile_sha256: Sha256
    observed_invocation_sha256: Sha256
    pid_one_observed: Literal[True]
    effective_uid_zero_observed: Literal[True]
    privileged_observed: Literal[True]
    pid_namespace_private_observed: Literal[True]
    mount_namespace_private_observed: Literal[True]
    user_namespace_identity_recorded: Literal[True]
    user_namespace_private_qualified: Literal[False]
    cgroup_namespace_private_observed: Literal[True]
    network_namespace_isolated_observed: Literal[True]
    single_threaded_before_fork: Literal[True]
    cgroup_root_initially_only_pid_one: Literal[True]
    fault_profile_id: Literal["bpe.native-qualification.pidfd-send-signal-eperm.v1"]
    outer_seccomp_instruction_contract_sha256: Sha256

    @field_validator(
        "pid_one_observed",
        "effective_uid_zero_observed",
        "privileged_observed",
        "pid_namespace_private_observed",
        "mount_namespace_private_observed",
        "user_namespace_identity_recorded",
        "cgroup_namespace_private_observed",
        "network_namespace_isolated_observed",
        "runtime_bpe_tree_matches_built_wheel",
        "single_threaded_before_fork",
        "cgroup_root_initially_only_pid_one",
        mode="before",
    )
    @classmethod
    def observations_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification container observations are incomplete")
        return value

    @field_validator("runtime_distributions", mode="before")
    @classmethod
    def distribution_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("user_namespace_private_qualified", mode="before")
    @classmethod
    def user_namespace_is_not_qualified(cls, value: object) -> object:
        if value is not False:
            raise ValueError("native qualification does not prove a private user namespace")
        return value

    @model_validator(mode="after")
    def fault_profile_is_exact(self) -> Self:
        if (
            sum(item.file_count for item in self.runtime_distributions)
            > MAX_NATIVE_QUALIFICATION_RUNTIME_FILES
            or sum(item.total_bytes for item in self.runtime_distributions)
            > MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES
        ):
            raise ValueError(
                "native qualification runtime distribution summary exceeds its work bound"
            )
        identities = tuple(
            (item.root, item.normalized_name, item.version)
            for item in self.runtime_distributions
        )
        if (
            self.outer_seccomp_instruction_contract_sha256
            != NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256
            or self.observed_invocation_sha256 != self.invocation.invocation_sha256
            or identities != tuple(sorted(identities))
            or len(set(identities)) != len(identities)
            or native_qualification_runtime_dependency_manifest_sha256(
                self.runtime_distributions
            )
            != self.runtime_dependency_manifest_sha256
        ):
            raise ValueError("native qualification container binding is inconsistent")
        bpe_distributions = tuple(
            item
            for item in self.runtime_distributions
            if item.root == "runtime" and item.normalized_name == "bpe"
        )
        if (
            len(bpe_distributions) != 1
            or bpe_distributions[0].version
            != NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION
            or bpe_distributions[0].aggregate_scope != "package-tree"
            or bpe_distributions[0].aggregate_tree_sha256
            != self.runtime_bpe_tree_manifest_sha256
        ):
            raise ValueError("native qualification runtime BPE tree is inconsistent")
        runtime_distribution_bytes = sum(
            item.total_bytes
            for item in self.runtime_distributions
            if item.root == "runtime"
        )
        if (
            self.runtime_root_tree_sha256 == self.runtime_bpe_tree_manifest_sha256
            or self.runtime_root_total_bytes <= runtime_distribution_bytes
        ):
            raise ValueError("native qualification whole runtime tree is inconsistent")
        dependency_distributions = tuple(
            item for item in self.runtime_distributions if item.root == "dependencies"
        )
        if (
            not dependency_distributions
            or sum(item.total_bytes for item in dependency_distributions)
            != self.dependency_root_total_bytes
        ):
            raise ValueError("native qualification dependency-root total is inconsistent")
        if any(
            item.aggregate_scope != "distribution-files"
            for item in self.runtime_distributions
            if item not in bpe_distributions
        ):
            raise ValueError("native qualification dependency scope is inconsistent")
        return self


class NativeQualificationBuildTools(_QualificationModel):
    compiler_identity: _BOUNDED_TEXT
    linker_identity: _BOUNDED_TEXT
    libc_identity: _BOUNDED_TEXT
    binutils_identity: _BOUNDED_TEXT


class NativeQualificationArtifactDuplicate(_QualificationModel):
    case_name: NativeQualificationCaseName
    duplicate_sha256: Sha256
    duplicate_size_bytes: Annotated[int, Field(ge=64, le=MAX_LAUNCHER_ARTIFACT_BYTES)]
    duplicate_device: Annotated[int, Field(ge=0)]
    duplicate_inode: Annotated[int, Field(ge=1)]
    duplicate_mode: Annotated[int, Field(ge=0, le=0o177777)]
    duplicate_nlink: Literal[0]
    duplicate_seals: Literal[63]
    duplicate_readonly_verified: Literal[True]
    duplicate_cloexec_verified: Literal[True]
    duplicate_identity_verified: Literal[True]
    executed_from_duplicate: Literal[True]

    @field_validator(
        "duplicate_readonly_verified",
        "duplicate_cloexec_verified",
        "duplicate_identity_verified",
        "executed_from_duplicate",
        mode="before",
    )
    @classmethod
    def duplicate_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification artifact duplicate was not exact")
        return value


class NativeQualificationArtifact(_QualificationModel):
    launcher_artifact_id: StableId
    launcher_sha256: Sha256
    launcher_source_sha256: Sha256
    launcher_size_bytes: Annotated[int, Field(ge=64, le=MAX_LAUNCHER_ARTIFACT_BYTES)]
    launcher_build_id_sha1: _SHA1
    build_tools: NativeQualificationBuildTools
    seccomp_policy_id: Literal["bpe.inert-fixture-launcher-seccomp.v1"]
    seccomp_policy_sha256: Sha256
    preflight_receipt: LinuxInertLauncherArtifactPreflightReceipt
    preflight_id: Sha256
    sealed_copy_sha256: Sha256
    sealed_copy_seals: Literal[63]
    sealed_copy_readonly_verified: Literal[True]
    sealed_copy_cloexec_verified: Literal[True]
    sealed_copy_identity_verified: Literal[True]
    source_artifact_unchanged_after_preflight: Literal[True]
    case_duplicates: Annotated[
        tuple[NativeQualificationArtifactDuplicate, ...],
        Field(
            min_length=len(NATIVE_QUALIFICATION_CASES),
            max_length=len(NATIVE_QUALIFICATION_CASES),
        ),
    ]

    @field_validator("case_duplicates", mode="before")
    @classmethod
    def duplicate_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator(
        "sealed_copy_readonly_verified",
        "sealed_copy_cloexec_verified",
        "sealed_copy_identity_verified",
        "source_artifact_unchanged_after_preflight",
        mode="before",
    )
    @classmethod
    def sealed_copy_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification sealed artifact binding was not exact")
        return value

    @model_validator(mode="after")
    def artifact_bindings_are_exact(self) -> Self:
        receipt = self.preflight_receipt
        if (
            self.launcher_artifact_id != receipt.launcher_artifact_id
            or self.launcher_sha256 != receipt.launcher_artifact_sha256
            or self.launcher_size_bytes != receipt.sealed_copy_size_bytes
            or self.seccomp_policy_id != FIXED_SECCOMP_POLICY_ID
            or self.seccomp_policy_id != receipt.launcher_seccomp_policy_id
            or self.seccomp_policy_sha256 != FIXED_SECCOMP_POLICY_SHA256
            or self.seccomp_policy_sha256 != receipt.launcher_seccomp_policy_sha256
            or self.preflight_id != receipt.preflight_id
            or self.sealed_copy_sha256 != receipt.sealed_copy_sha256
            or self.sealed_copy_sha256 != self.launcher_sha256
            or self.sealed_copy_seals != REQUIRED_EXEC_SEALS
            or self.sealed_copy_seals != receipt.sealed_copy_seals
        ):
            raise ValueError("native qualification artifact and preflight receipt differ")
        if tuple(item.case_name for item in self.case_duplicates) != NATIVE_QUALIFICATION_CASES:
            raise ValueError("native qualification artifact duplicates have the wrong cases")
        for item in self.case_duplicates:
            if (
                item.duplicate_sha256 != self.launcher_sha256
                or item.duplicate_size_bytes != self.launcher_size_bytes
                or item.duplicate_mode != SEALED_EXECUTABLE_MODE
                or item.duplicate_nlink != 0
                or item.duplicate_seals != self.sealed_copy_seals
            ):
                raise ValueError("native qualification case duplicate differs from artifact")
        duplicate_identities = {
            (item.duplicate_device, item.duplicate_inode)
            for item in self.case_duplicates
        }
        if len(duplicate_identities) != 1:
            raise ValueError("native qualification case duplicates changed sealed identity")
        return self


class NativeQualificationInjection(_QualificationModel):
    contract_id: StableId
    unexpected_inherited_descriptor: Literal[257] | None
    prequeued_control_payload_hex: Literal["78"] | None
    control_peer_closed_before_exec: bool
    outer_seccomp_fault_profile_id: (
        Literal["bpe.native-qualification.pidfd-send-signal-eperm.v1"] | None
    )


class NativeQualificationSocketRecord(_QualificationModel):
    payload_hex: _FRAME_HEX
    message_truncated: Literal[False]
    control_truncated: Literal[False]
    ancillary_present: Literal[False]

    @field_validator(
        "message_truncated",
        "control_truncated",
        "ancillary_present",
        mode="before",
    )
    @classmethod
    def unsafe_record_facts_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("qualified native records cannot be truncated or ancillary")
        return value

    def to_native_record(self) -> InertNativeSocketRecord:
        return InertNativeSocketRecord(
            payload=bytes.fromhex(self.payload_hex),
            message_truncated=self.message_truncated,
            control_truncated=self.control_truncated,
            ancillary_present=self.ancillary_present,
        )


NativeQualificationFrameName = Literal[
    "hello",
    "child_ready",
    "child_signaled",
    "child_observed",
    "final",
    "error",
]
NativeQualificationStageName = Literal[
    "startup",
    "descriptor_validation",
    "cgroup_validation",
    "fixture_setup",
    "clone3",
    "child_ready",
    "pidfd_signal",
    "cgroup_kill",
    "child_observation",
    "child_reap",
    "cleanup",
    "protocol",
]
NativeQualificationReasonName = Literal[
    "bad_argc",
    "bad_argv",
    "nonempty_environment",
    "bad_descriptor_layout",
    "bad_stdio",
    "bad_control_socket",
    "bad_cgroup_descriptor",
    "cgroup_not_empty",
    "protocol_input",
    "peer_closed",
    "resource_exhausted",
    "clone3_unavailable",
    "clone3_rejected",
    "pidfd_unavailable",
    "child_setup_failed",
    "pidfd_signal_failed",
    "cgroup_kill_failed",
    "child_observation_failed",
    "child_reap_failed",
    "timeout",
    "cleanup_incomplete",
    "io_failure",
    "internal",
]


class NativeQualificationTranscriptProjection(_QualificationModel):
    succeeded: bool
    frame_types: Annotated[
        tuple[NativeQualificationFrameName, ...],
        Field(min_length=1, max_length=5),
    ]
    launcher_exit_code: Annotated[int, Field(ge=0, le=255)]
    launcher_pid: _PID
    child_pid: _PID | None
    achieved_result_mask: Annotated[int, Field(ge=0, le=ACHIEVED_RESULT_MASK)]
    elapsed_ns: Annotated[int, Field(ge=1, le=45_000_000_000)] | None
    failure_stage: NativeQualificationStageName | None
    failure_reason: NativeQualificationReasonName | None
    failure_errno: Annotated[int, Field(ge=0, le=PROTOCOL_MAX_ERRNO)] | None

    @field_validator("frame_types", mode="before")
    @classmethod
    def frame_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def success_and_failure_shapes_are_disjoint(self) -> Self:
        if self.succeeded:
            if (
                self.elapsed_ns is None
                or self.failure_stage is not None
                or self.failure_reason is not None
                or self.failure_errno is not None
            ):
                raise ValueError("successful native projection contains failure fields")
        elif (
            self.elapsed_ns is not None
            or self.failure_stage is None
            or self.failure_reason is None
            or self.failure_errno is None
        ):
            raise ValueError("failed native projection is incomplete")
        return self


class NativeQualificationCaseCleanup(_QualificationModel):
    cleanup_method: Literal["exact-wait-empty-rmdir-v1"]
    launcher_waited_exact: Literal[True]
    no_reparented_child_observed: Literal[True]
    leaf_cgroup_procs_empty: Literal[True]
    leaf_populated_zero: Literal[True]
    leaf_removed: Literal[True]
    evaluator_fallback_cleanup_used: Literal[False]

    @field_validator(
        "launcher_waited_exact",
        "no_reparented_child_observed",
        "leaf_cgroup_procs_empty",
        "leaf_populated_zero",
        "leaf_removed",
        mode="before",
    )
    @classmethod
    def cleanup_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification case cleanup is incomplete")
        return value

    @field_validator("evaluator_fallback_cleanup_used", mode="before")
    @classmethod
    def evaluator_fallback_must_not_be_used(cls, value: object) -> object:
        if value is not False:
            raise ValueError("qualified case required evaluator fallback cleanup")
        return value


_INJECTION_CONTRACTS: dict[NativeQualificationCaseName, dict[str, object]] = {
    "success": {
        "contract_id": "bpe.native-qualification.injection.none.v1",
        "unexpected_inherited_descriptor": None,
        "prequeued_control_payload_hex": None,
        "control_peer_closed_before_exec": False,
        "outer_seccomp_fault_profile_id": None,
    },
    "extra-fd": {
        "contract_id": "bpe.native-qualification.injection.descriptor-257.v1",
        "unexpected_inherited_descriptor": 257,
        "prequeued_control_payload_hex": None,
        "control_peer_closed_before_exec": False,
        "outer_seccomp_fault_profile_id": None,
    },
    "inbound": {
        "contract_id": "bpe.native-qualification.injection.control-byte-78.v1",
        "unexpected_inherited_descriptor": None,
        "prequeued_control_payload_hex": "78",
        "control_peer_closed_before_exec": False,
        "outer_seccomp_fault_profile_id": None,
    },
    "peer-close": {
        "contract_id": "bpe.native-qualification.injection.peer-close-before-exec.v1",
        "unexpected_inherited_descriptor": None,
        "prequeued_control_payload_hex": None,
        "control_peer_closed_before_exec": True,
        "outer_seccomp_fault_profile_id": None,
    },
    "emergency-cgroup-kill": {
        "contract_id": "bpe.native-qualification.injection.pidfd-eperm.v1",
        "unexpected_inherited_descriptor": None,
        "prequeued_control_payload_hex": None,
        "control_peer_closed_before_exec": False,
        "outer_seccomp_fault_profile_id": NATIVE_QUALIFICATION_FAULT_PROFILE_ID,
    },
}

_REJECTION_CATEGORIES: dict[
    NativeQualificationCaseName,
    Literal["empty_transcript", "eof_not_observed"],
] = {
    "inbound": "empty_transcript",
    "peer-close": "eof_not_observed",
}

_CASE_SET_EXPECTATIONS: dict[NativeQualificationCaseName, dict[str, object]] = {
    "success": {
        "returncode": int(NativeExitCode.OK),
        "eof_observed": True,
        "parser_outcome": "accepted",
        "frame_types": (
            "hello",
            "child_ready",
            "child_signaled",
            "child_observed",
            "final",
        ),
        "succeeded": True,
        "achieved_result_mask": 0x1FF,
    },
    "extra-fd": {
        "returncode": int(NativeExitCode.STARTUP),
        "eof_observed": True,
        "parser_outcome": "accepted",
        "frame_types": ("error",),
        "succeeded": False,
        "achieved_result_mask": 0,
        "failure_stage": "descriptor_validation",
        "failure_reason": "bad_descriptor_layout",
        "failure_errno": 0,
    },
    "inbound": {
        "returncode": int(NativeExitCode.STARTUP),
        "eof_observed": True,
        "parser_outcome": "rejected",
        "parser_rejection": _REJECTION_CATEGORIES["inbound"],
        "record_count": 0,
    },
    "peer-close": {
        "returncode": int(NativeExitCode.PROTOCOL),
        "eof_observed": False,
        "parser_outcome": "rejected",
        "parser_rejection": _REJECTION_CATEGORIES["peer-close"],
        "record_count": 0,
    },
    "emergency-cgroup-kill": {
        "returncode": int(NativeExitCode.KERNEL),
        "eof_observed": True,
        "parser_outcome": "accepted",
        "frame_types": ("hello", "child_ready", "error"),
        "succeeded": False,
        "achieved_result_mask": 0x1C3,
        "failure_stage": "pidfd_signal",
        "failure_reason": "pidfd_signal_failed",
        "failure_errno": 1,
        "cleanup_evidence_scope": "outcome-under-trusted-kernel-assumptions",
    },
}

NATIVE_QUALIFICATION_CASE_SET_SHA256 = sha256_bytes(
    NATIVE_QUALIFICATION_CASE_SET_DOMAIN
    + canonical_json_bytes(
        {
            "case_set_id": NATIVE_QUALIFICATION_CASE_SET_ID,
            "parser_contract_id": NATIVE_QUALIFICATION_PARSER_ID,
            "launcher_protocol_id": NATIVE_QUALIFICATION_LAUNCHER_PROTOCOL_ID,
            "outer_seccomp_instruction_contract_sha256": (
                NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256
            ),
            "cases": tuple(
                {
                    "case_name": case_name,
                    "injection": _INJECTION_CONTRACTS[case_name],
                    "expected": _CASE_SET_EXPECTATIONS[case_name],
                }
                for case_name in NATIVE_QUALIFICATION_CASES
            ),
            "cleanup_contract": {
                "cleanup_method": "exact-wait-empty-rmdir-v1",
                "launcher_waited_exact": True,
                "no_reparented_child_observed": True,
                "leaf_cgroup_procs_empty": True,
                "leaf_populated_zero": True,
                "leaf_removed": True,
                "evaluator_fallback_cleanup_used": False,
            },
        }
    )
)


def _projection_for(transcript: InertNativeTranscript) -> NativeQualificationTranscriptProjection:
    return NativeQualificationTranscriptProjection(
        succeeded=transcript.succeeded,
        frame_types=cast(
            tuple[NativeQualificationFrameName, ...],
            tuple(frame.frame_type.name.lower() for frame in transcript.frames),
        ),
        launcher_exit_code=int(transcript.launcher_exit_code),
        launcher_pid=transcript.launcher_pid,
        child_pid=transcript.child_pid,
        achieved_result_mask=transcript.achieved_result_mask,
        elapsed_ns=transcript.elapsed_ns,
        failure_stage=cast(
            NativeQualificationStageName | None,
            (
                transcript.failure_stage.name.lower()
                if transcript.failure_stage is not None
                else None
            ),
        ),
        failure_reason=cast(
            NativeQualificationReasonName | None,
            (
                transcript.failure_reason.name.lower()
                if transcript.failure_reason is not None
                else None
            ),
        ),
        failure_errno=transcript.failure_errno,
    )


class NativeQualificationCase(_QualificationModel):
    case_name: NativeQualificationCaseName
    injection: NativeQualificationInjection
    launcher_pid: _PID
    returncode: Annotated[int, Field(ge=0, le=255)]
    eof_observed: bool
    records: Annotated[
        tuple[NativeQualificationSocketRecord, ...],
        Field(max_length=PROTOCOL_MAX_FRAMES),
    ]
    transcript_sha256: Sha256
    parser_outcome: Literal["accepted", "rejected"]
    parser_projection: NativeQualificationTranscriptProjection | None
    parser_rejection: Literal["empty_transcript", "eof_not_observed"] | None
    cleanup: NativeQualificationCaseCleanup

    @field_validator("records", mode="before")
    @classmethod
    def record_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    def _transcript_preimage(self) -> dict[str, object]:
        return {
            "case_name": self.case_name,
            "injection": self.injection.model_dump(mode="python"),
            "launcher_pid": self.launcher_pid,
            "returncode": self.returncode,
            "eof_observed": self.eof_observed,
            "records": [record.model_dump(mode="python") for record in self.records],
        }

    @model_validator(mode="after")
    def injection_digest_and_replay_are_exact(self) -> Self:
        if self.injection.model_dump(mode="python") != _INJECTION_CONTRACTS[self.case_name]:
            raise ValueError("native qualification case injection is inconsistent")
        expected_digest = sha256_bytes(
            NATIVE_QUALIFICATION_TRANSCRIPT_DOMAIN
            + canonical_json_bytes(self._transcript_preimage())
        )
        if self.transcript_sha256 != expected_digest:
            raise ValueError("native qualification transcript digest is inconsistent")

        records = tuple(record.to_native_record() for record in self.records)
        try:
            transcript = parse_inert_native_transcript(
                records,
                returncode=self.returncode,
                eof_observed=self.eof_observed,
                expected_launcher_pid=self.launcher_pid,
            )
        except InertNativeProtocolViolation as exc:
            expected_rejection = {
                "inbound": (
                    _REJECTION_CATEGORIES["inbound"],
                    int(NativeExitCode.STARTUP),
                    True,
                ),
                "peer-close": (
                    _REJECTION_CATEGORIES["peer-close"],
                    int(NativeExitCode.PROTOCOL),
                    False,
                ),
            }.get(self.case_name)
            if (
                expected_rejection is None
                or self.parser_outcome != "rejected"
                or self.parser_projection is not None
                or self.parser_rejection != expected_rejection[0]
                or self.returncode != expected_rejection[1]
                or self.eof_observed is not expected_rejection[2]
                or self.records
            ):
                raise ValueError("native qualification parser rejection is inconsistent") from exc
            return self

        if (
            self.case_name in {"inbound", "peer-close"}
            or self.parser_outcome != "accepted"
            or self.parser_rejection is not None
            or self.parser_projection != _projection_for(transcript)
        ):
            raise ValueError("native qualification parser projection is inconsistent")

        projection = self.parser_projection
        if projection is None:  # pragma: no cover - guarded above
            raise ValueError("native qualification parser projection is missing")
        if self.case_name == "success":
            valid = (
                projection.succeeded
                and projection.frame_types
                == ("hello", "child_ready", "child_signaled", "child_observed", "final")
                and projection.launcher_exit_code == int(NativeExitCode.OK)
                and projection.child_pid is not None
                and projection.achieved_result_mask == ACHIEVED_RESULT_MASK == 0x1FF
                and projection.elapsed_ns is not None
            )
        elif self.case_name == "extra-fd":
            valid = (
                not projection.succeeded
                and projection.frame_types == ("error",)
                and projection.launcher_exit_code == int(NativeExitCode.STARTUP)
                and projection.child_pid is None
                and projection.achieved_result_mask == 0
                and projection.failure_stage == "descriptor_validation"
                and projection.failure_reason == "bad_descriptor_layout"
                and projection.failure_errno == 0
            )
        else:
            valid = (
                self.case_name == "emergency-cgroup-kill"
                and not projection.succeeded
                and projection.frame_types == ("hello", "child_ready", "error")
                and projection.launcher_exit_code == int(NativeExitCode.KERNEL)
                and projection.child_pid is not None
                and projection.achieved_result_mask == 0x1C3
                and projection.failure_stage == "pidfd_signal"
                and projection.failure_reason == "pidfd_signal_failed"
                and projection.failure_errno == 1
            )
        if not valid:
            raise ValueError("native qualification case result is not the fixed result")
        return self


class NativeQualificationFinalization(_QualificationModel):
    probe_restored_to_cgroup_namespace_root: Literal[True]
    manager_cgroup_empty: Literal[True]
    manager_cgroup_removed: Literal[True]
    every_launcher_duplicate_closed: Literal[True]
    retained_artifact_closed: Literal[True]
    source_artifact_descriptor_closed: Literal[True]

    @field_validator(
        "probe_restored_to_cgroup_namespace_root",
        "manager_cgroup_empty",
        "manager_cgroup_removed",
        "every_launcher_duplicate_closed",
        "retained_artifact_closed",
        "source_artifact_descriptor_closed",
        mode="before",
    )
    @classmethod
    def finalization_claims_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification finalization is incomplete")
        return value


def native_qualification_github_context_bytes(
    source_run: NativeQualificationSourceRun,
    host: NativeQualificationHost,
    container: NativeQualificationContainer,
    artifact: NativeQualificationArtifact,
) -> bytes:
    """Reconstruct the exact canonical workflow provenance document from a report."""

    upstream = source_run.upstream_workflow_run
    invocation = container.invocation
    tools = artifact.build_tools
    return canonical_json_bytes(
        {
            "git_commit": source_run.git_commit,
            "github_sha": source_run.github_sha,
            "github_run_id": source_run.github_run_id,
            "github_run_attempt": source_run.github_run_attempt,
            "github_repository": source_run.github_repository,
            "github_job": source_run.github_job,
            "github_event": source_run.github_event,
            "github_ref": source_run.github_ref,
            "github_actor_category": source_run.github_actor_category,
            "upstream_workflow_name": upstream.workflow_name,
            "upstream_workflow_id": upstream.workflow_id,
            "upstream_workflow_path": upstream.workflow_path,
            "upstream_run_id": upstream.run_id,
            "upstream_run_attempt": upstream.run_attempt,
            "upstream_event": upstream.event,
            "upstream_head_branch": upstream.head_branch,
            "upstream_head_repository_full_name": upstream.head_repository_full_name,
            "upstream_head_sha": upstream.head_sha,
            "upstream_conclusion": upstream.conclusion,
            "built_wheel_sha256": source_run.built_wheel_sha256,
            "runner_architecture": host.runner_architecture,
            "docker_server_architecture": host.docker_server_architecture,
            "docker_server_version": container.docker_server_version,
            "image_reference": invocation.image_reference,
            "image_manifest_sha256": invocation.image_manifest_sha256,
            "image_platform_sha256": invocation.image_platform_sha256,
            "image_config_sha256": invocation.image_config_sha256,
            "runtime_name": container.runtime_name,
            "runtime_version": container.runtime_version,
            "runtime_id": container.runtime_id,
            "compiler_identity": tools.compiler_identity,
            "linker_identity": tools.linker_identity,
            "libc_identity": tools.libc_identity,
            "binutils_identity": tools.binutils_identity,
            "launcher_build_id_sha1": artifact.launcher_build_id_sha1,
        }
    )


class LinuxInertLauncherNativeQualificationReport(_QualificationModel):
    """Unsigned, replayable evidence for the exact fixed native qualification cases."""

    schema_version: Literal["bpe.linux-inert-launcher-native-qualification-report.v1"]
    status: Literal["native_probe_passed_unsigned"]
    qualification_id: Sha256
    qualification_nonce: Sha256
    qualification_nonce_method: Literal["secrets-token-bytes-256-bit-v1"]
    qualification_nonce_purpose: Literal["run-correlation-only"]
    parser_contract_id: Literal["bpe.inert-native-transcript-parser.v1"]
    case_set_id: Literal["bpe.linux-inert-launcher-native-case-set.v1"]
    case_set_sha256: Sha256
    context_sha256: Sha256
    source_run: NativeQualificationSourceRun
    host: NativeQualificationHost
    container: NativeQualificationContainer
    artifact: NativeQualificationArtifact
    cases: Annotated[
        tuple[NativeQualificationCase, ...],
        Field(
            min_length=len(NATIVE_QUALIFICATION_CASES),
            max_length=len(NATIVE_QUALIFICATION_CASES),
        ),
    ]
    finalization: NativeQualificationFinalization
    preflight_before_process_creation_verified: Literal[True]
    launcher_execution_started: Literal[True]
    fixture_execution_started: Literal[True]
    launcher_process_count: Literal[5]
    fixture_child_process_count: Literal[2]
    execution_scope: Literal["evaluator-only-native-qualification"]
    production_launch_admission_used: Literal[False]
    production_launch_attempts_consumed: Literal[0]
    authenticity: Literal["unsigned"]
    durable: Literal[False]
    sigstore_attested: Literal[False]
    worm_archived: Literal[False]
    provenance_authenticated: Literal[False]
    externally_anchored: Literal[False]
    freshness_authenticated: Literal[False]
    authoritative: Literal[False]
    execution_authorized: Literal[False]
    fixture_child_exec_performed: Literal[False]
    candidate_bytes_accessed: Literal[False]
    evaluation_job_bytes_accessed: Literal[False]
    resource_pressure_qualified: Literal[False]
    descendant_tree_cleanup_qualified: Literal[False]
    filesystem_isolation_qualified: Literal[False]
    network_isolation_qualified: Literal[False]
    signed_deadlines_qualified: Literal[False]
    signed_output_limits_qualified: Literal[False]
    production_orchestration_qualified: Literal[False]
    official_grading_qualified: Literal[False]

    @field_validator("cases", mode="before")
    @classmethod
    def case_arrays_are_tuples(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator(
        "preflight_before_process_creation_verified",
        "launcher_execution_started",
        "fixture_execution_started",
        mode="before",
    )
    @classmethod
    def positive_execution_facts_must_be_boolean_true(cls, value: object) -> object:
        if value is not True:
            raise ValueError("native qualification execution facts are incomplete")
        return value

    @field_validator(
        "durable",
        "sigstore_attested",
        "worm_archived",
        "provenance_authenticated",
        "externally_anchored",
        "freshness_authenticated",
        "authoritative",
        "execution_authorized",
        "production_launch_admission_used",
        "fixture_child_exec_performed",
        "candidate_bytes_accessed",
        "evaluation_job_bytes_accessed",
        "resource_pressure_qualified",
        "descendant_tree_cleanup_qualified",
        "filesystem_isolation_qualified",
        "network_isolation_qualified",
        "signed_deadlines_qualified",
        "signed_output_limits_qualified",
        "production_orchestration_qualified",
        "official_grading_qualified",
        mode="before",
    )
    @classmethod
    def nonclaims_must_be_boolean_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("native qualification report crossed its authority boundary")
        return value

    @model_validator(mode="after")
    def identity_case_set_and_artifact_are_exact(self) -> Self:
        if self.qualification_nonce == "0" * 64:
            raise ValueError("native qualification nonce cannot be an all-zero placeholder")
        if (
            self.parser_contract_id != NATIVE_QUALIFICATION_PARSER_ID
            or self.case_set_id != NATIVE_QUALIFICATION_CASE_SET_ID
            or self.case_set_sha256 != NATIVE_QUALIFICATION_CASE_SET_SHA256
            or self.artifact.preflight_receipt.launcher_protocol_version
            != NATIVE_QUALIFICATION_LAUNCHER_PROTOCOL_ID
        ):
            raise ValueError("native qualification case-set identity is inconsistent")
        if tuple(item.case_name for item in self.cases) != NATIVE_QUALIFICATION_CASES:
            raise ValueError("native qualification cases have the wrong order or membership")
        if tuple(item.case_name for item in self.artifact.case_duplicates) != tuple(
            item.case_name for item in self.cases
        ):
            raise ValueError("native qualification artifact duplicates differ from cases")
        critical_files = {
            item.path: item.sha256 for item in self.source_run.source_manifest.files
        }
        bpe_distribution = next(
            item
            for item in self.container.runtime_distributions
            if item.root == "runtime" and item.normalized_name == "bpe"
        )
        committed_bpe_files = tuple(
            item
            for item in self.source_run.source_manifest.files
            if item.path in NATIVE_QUALIFICATION_BPE_SOURCE_PATHS
        )
        if (
            self.container.runtime_distribution_wheel_sha256
            != self.source_run.built_wheel_sha256
            or self.source_run.built_wheel_bpe_tree_manifest_sha256
            != self.source_run.commit_bpe_tree_manifest_sha256
            or self.container.runtime_bpe_tree_manifest_sha256
            != self.source_run.built_wheel_bpe_tree_manifest_sha256
            or bpe_distribution.file_count != len(committed_bpe_files)
            or bpe_distribution.total_bytes
            != sum(item.size_bytes for item in committed_bpe_files)
            or self.container.runtime_probe_source_sha256
            != critical_files["tests/integration/inert_fixture_launcher_native_probe.py"]
            or self.container.runtime_lockfile_sha256 != critical_files["uv.lock"]
            or self.artifact.launcher_source_sha256
            != critical_files["worker/linux/inert_fixture_launcher/launcher.c"]
        ):
            raise ValueError("native qualification runtime and source evidence differ")
        provenance_bytes = native_qualification_github_context_bytes(
            self.source_run,
            self.host,
            self.container,
            self.artifact,
        )
        if (
            self.source_run.github_context_file_sha256
            != sha256_bytes(provenance_bytes)
            or self.source_run.github_context_file_size_bytes != len(provenance_bytes)
        ):
            raise ValueError(
                "native qualification canonical provenance binding is inconsistent"
            )
        mount_bindings = {
            item.purpose: item for item in self.container.invocation.mount_bindings
        }
        expected_mount_sources: dict[
            NativeQualificationMountPurpose,
            tuple[str | None, int | None],
        ] = {
            "provenance-context": (
                self.source_run.github_context_file_sha256,
                self.source_run.github_context_file_size_bytes,
            ),
            "tracked-tree-manifest": (
                self.source_run.tracked_tree_content_manifest_sha256,
                self.source_run.tracked_tree_manifest_file_size_bytes,
            ),
            "built-wheel": (
                self.source_run.built_wheel_sha256,
                self.source_run.built_wheel_size_bytes,
            ),
            "probe": (
                critical_files[
                    "tests/integration/inert_fixture_launcher_native_probe.py"
                ],
                self.source_run.probe_source_size_bytes,
            ),
            "launcher": (
                self.artifact.launcher_sha256,
                self.artifact.launcher_size_bytes,
            ),
            "dependency-tree": (
                self.container.dependency_root_tree_sha256,
                self.container.dependency_root_total_bytes,
            ),
            "source-tree": (
                self.source_run.source_manifest.manifest_sha256,
                self.source_run.source_manifest_total_bytes,
            ),
            "qualification-output": (None, None),
        }
        if any(
            (
                mount_bindings[purpose].source_sha256,
                mount_bindings[purpose].source_size_bytes,
            )
            != expected
            for purpose, expected in expected_mount_sources.items()
        ):
            raise ValueError("native qualification invocation mounts are not cross-bound")
        expected_context = native_qualification_context_sha256(
            git_commit=self.source_run.git_commit,
            source_manifest_sha256=self.source_run.source_manifest.manifest_sha256,
            tracked_tree_content_manifest_sha256=(
                self.source_run.tracked_tree_content_manifest_sha256
            ),
            tracked_tree_matches_git_commit=(
                self.source_run.tracked_tree_matches_git_commit
            ),
            built_wheel_sha256=self.source_run.built_wheel_sha256,
            runtime_dependency_manifest_sha256=(
                self.container.runtime_dependency_manifest_sha256
            ),
            runtime_root_tree_sha256=self.container.runtime_root_tree_sha256,
            runtime_root_total_bytes=self.container.runtime_root_total_bytes,
            runtime_root_tree_completeness_method=(
                self.container.runtime_root_tree_completeness_method
            ),
            launcher_sha256=self.artifact.launcher_sha256,
            workflow_sha256=self.source_run.workflow_sha256,
            github_repository=self.source_run.github_repository,
            github_sha=self.source_run.github_sha,
            github_run_id=self.source_run.github_run_id,
            github_run_attempt=self.source_run.github_run_attempt,
            github_job=self.source_run.github_job,
            github_event=self.source_run.github_event,
            github_ref=self.source_run.github_ref,
            github_actor_category=self.source_run.github_actor_category,
            upstream_workflow_run=self.source_run.upstream_workflow_run,
            container_invocation_sha256=self.container.invocation.invocation_sha256,
        )
        if self.context_sha256 != expected_context:
            raise ValueError("native qualification context digest is inconsistent")
        expected = inert_native_qualification_id(
            self.model_dump(mode="python", exclude={"qualification_id"})
        )
        if self.qualification_id != expected:
            raise ValueError("native qualification identity is inconsistent")
        if len(canonical_json_bytes(self)) > MAX_NATIVE_QUALIFICATION_REPORT_BYTES:
            raise ValueError("native qualification report exceeds the fixed byte boundary")
        return self


def native_qualification_context_sha256(
    *,
    git_commit: str,
    source_manifest_sha256: str,
    tracked_tree_content_manifest_sha256: str,
    tracked_tree_matches_git_commit: bool,
    built_wheel_sha256: str,
    runtime_dependency_manifest_sha256: str,
    runtime_root_tree_sha256: str,
    runtime_root_total_bytes: int,
    runtime_root_tree_completeness_method: Literal[
        "recursive-lstat-exact-wheel-projection-v1"
    ],
    launcher_sha256: str,
    workflow_sha256: str,
    github_repository: Literal["synechism/bpe"],
    github_sha: str,
    github_run_id: int,
    github_run_attempt: int,
    github_job: Literal["native-qualification"],
    github_event: Literal["workflow_run"],
    github_ref: Literal["refs/heads/main"],
    github_actor_category: NativeQualificationActorCategory,
    upstream_workflow_run: NativeQualificationUpstreamWorkflowRun,
    container_invocation_sha256: str,
) -> str:
    """Return the strict domain-separated cross-layer execution-context digest."""

    try:
        binding = NativeQualificationContextBinding.model_validate(
            {
                "git_commit": git_commit,
                "source_manifest_sha256": source_manifest_sha256,
                "tracked_tree_content_manifest_sha256": (
                    tracked_tree_content_manifest_sha256
                ),
                "tracked_tree_matches_git_commit": tracked_tree_matches_git_commit,
                "built_wheel_sha256": built_wheel_sha256,
                "runtime_dependency_manifest_sha256": (
                    runtime_dependency_manifest_sha256
                ),
                "runtime_root_tree_sha256": runtime_root_tree_sha256,
                "runtime_root_total_bytes": runtime_root_total_bytes,
                "runtime_root_tree_completeness_method": (
                    runtime_root_tree_completeness_method
                ),
                "launcher_sha256": launcher_sha256,
                "workflow_sha256": workflow_sha256,
                "github_repository": github_repository,
                "github_sha": github_sha,
                "github_run_id": github_run_id,
                "github_run_attempt": github_run_attempt,
                "github_job": github_job,
                "github_event": github_event,
                "github_ref": github_ref,
                "github_actor_category": github_actor_category,
                "upstream_workflow_run": upstream_workflow_run,
                "container_invocation_sha256": container_invocation_sha256,
            },
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification context binding is invalid"
        ) from exc
    return sha256_bytes(
        NATIVE_QUALIFICATION_CONTEXT_DOMAIN
        + canonical_json_bytes(binding.model_dump(mode="python"))
    )


def inert_native_qualification_id(report_fields: Mapping[str, object]) -> str:
    """Return the domain-separated report ID for fields without ``qualification_id``."""

    if "qualification_id" in report_fields:
        raise ValueError("native qualification identity input contains its own digest")
    return sha256_bytes(
        NATIVE_QUALIFICATION_DOMAIN + canonical_json_bytes(dict(report_fields))
    )


def build_inert_native_qualification_source_manifest(
    file_evidence: tuple[tuple[Sha256, int], ...],
) -> NativeQualificationSourceManifest:
    """Bind ordered critical-file digests and sizes to the fixed source contract."""

    try:
        if type(file_evidence) is not tuple or len(file_evidence) != len(
            NATIVE_QUALIFICATION_SOURCE_PATHS
        ):
            raise ValueError("native qualification source evidence has the wrong shape")
        if any(type(item) is not tuple or len(item) != 2 for item in file_evidence):
            raise ValueError("native qualification source evidence is malformed")
        fields: dict[str, object] = {
            "schema_version": "bpe.linux-inert-launcher-native-source-manifest.v1",
            "files": tuple(
                {"path": path, "sha256": digest, "size_bytes": size_bytes}
                for path, (digest, size_bytes) in zip(
                    NATIVE_QUALIFICATION_SOURCE_PATHS,
                    file_evidence,
                    strict=True,
                )
            ),
        }
        fields["manifest_sha256"] = sha256_bytes(
            NATIVE_QUALIFICATION_SOURCE_MANIFEST_DOMAIN
            + canonical_json_bytes(fields)
        )
        return NativeQualificationSourceManifest.model_validate(fields, strict=True)
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification source manifest could not be built"
        ) from exc


def build_inert_native_qualification_case(
    *,
    case_name: NativeQualificationCaseName,
    launcher_pid: int,
    returncode: int,
    eof_observed: bool,
    records: tuple[InertNativeSocketRecord, ...],
    cleanup: NativeQualificationCaseCleanup | Mapping[str, object],
) -> NativeQualificationCase:
    """Build one fixed case while deriving injection, digest, and replay outcome."""

    try:
        if type(records) is not tuple or any(
            type(record) is not InertNativeSocketRecord
            or type(record.payload) is not bytes
            for record in records
        ):
            raise ValueError("native qualification case records have the wrong shape")
        native_records = tuple(
            NativeQualificationSocketRecord.model_validate(
                {
                    "payload_hex": record.payload.hex(),
                    "message_truncated": record.message_truncated,
                    "control_truncated": record.control_truncated,
                    "ancillary_present": record.ancillary_present,
                },
                strict=True,
            )
            for record in records
        )
        injection = NativeQualificationInjection.model_validate(
            _INJECTION_CONTRACTS[case_name],
            strict=True,
        )
        try:
            transcript = parse_inert_native_transcript(
                records,
                returncode=returncode,
                eof_observed=eof_observed,
                expected_launcher_pid=launcher_pid,
            )
        except InertNativeProtocolViolation:
            parser_outcome: Literal["accepted", "rejected"] = "rejected"
            parser_projection = None
            parser_rejection = _REJECTION_CATEGORIES.get(case_name)
        else:
            parser_outcome = "accepted"
            parser_projection = _projection_for(transcript)
            parser_rejection = None

        preimage: dict[str, object] = {
            "case_name": case_name,
            "injection": injection.model_dump(mode="python"),
            "launcher_pid": launcher_pid,
            "returncode": returncode,
            "eof_observed": eof_observed,
            "records": [record.model_dump(mode="python") for record in native_records],
        }
        fields: dict[str, object] = {
            **preimage,
            "transcript_sha256": sha256_bytes(
                NATIVE_QUALIFICATION_TRANSCRIPT_DOMAIN
                + canonical_json_bytes(preimage)
            ),
            "parser_outcome": parser_outcome,
            "parser_projection": parser_projection,
            "parser_rejection": parser_rejection,
            "cleanup": cleanup,
        }
        return NativeQualificationCase.model_validate(fields, strict=True)
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification case could not be built"
        ) from exc


def replay_inert_native_qualification_case(
    case: NativeQualificationCase | Mapping[str, object],
) -> NativeQualificationTranscriptProjection | None:
    """Strictly reconstruct and replay one fixed case, returning its stored projection."""

    payload = case.model_dump(mode="python") if isinstance(case, NativeQualificationCase) else case
    try:
        validated = NativeQualificationCase.model_validate(payload, strict=True)
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification case failed strict replay validation"
        ) from exc
    return validated.parser_projection


def validate_inert_native_qualification_report(
    report: LinuxInertLauncherNativeQualificationReport | Mapping[str, object],
) -> LinuxInertLauncherNativeQualificationReport:
    """Freeze and replay-validate a complete report without inspecting the host."""

    payload = (
        report.model_dump(mode="python")
        if isinstance(report, LinuxInertLauncherNativeQualificationReport)
        else report
    )
    try:
        return LinuxInertLauncherNativeQualificationReport.model_validate(
            payload,
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification report failed strict replay validation"
        ) from exc


def canonical_inert_native_qualification_report_bytes(
    report: LinuxInertLauncherNativeQualificationReport | Mapping[str, object],
) -> bytes:
    """Return exact canonical bytes after complete replay validation."""

    return canonical_json_bytes(validate_inert_native_qualification_report(report))


def validate_inert_native_qualification_report_bytes(
    raw: bytes,
) -> LinuxInertLauncherNativeQualificationReport:
    """Validate bounded, duplicate-free JSON and require its exact canonical encoding."""

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_NATIVE_QUALIFICATION_REPORT_BYTES:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification report bytes exceed the fixed boundary"
        )
    try:
        parsed = strict_json_loads(raw)
        if type(parsed) is not dict:
            raise ValueError("native qualification report must be a JSON object")
        report = validate_inert_native_qualification_report(parsed)
        if raw != canonical_json_bytes(report):
            raise ValueError("native qualification report bytes are not canonical")
        return report
    except LinuxInertLauncherNativeQualificationError:
        raise
    except (TypeError, ValueError, ValidationError) as exc:
        raise LinuxInertLauncherNativeQualificationError(
            "native qualification report bytes failed strict replay validation"
        ) from exc


JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    "linux-inert-launcher-native-qualification-report-v1.json": (
        LinuxInertLauncherNativeQualificationReport
    ),
}


__all__ = [
    "JSON_SCHEMAS",
    "MAX_NATIVE_QUALIFICATION_BUILT_WHEEL_BYTES",
    "MAX_NATIVE_QUALIFICATION_PROVENANCE_BYTES",
    "MAX_NATIVE_QUALIFICATION_REPORT_BYTES",
    "MAX_NATIVE_QUALIFICATION_RUNTIME_DISTRIBUTIONS",
    "MAX_NATIVE_QUALIFICATION_RUNTIME_FILES",
    "MAX_NATIVE_QUALIFICATION_RUNTIME_TOTAL_BYTES",
    "MAX_NATIVE_QUALIFICATION_SOURCE_FILE_BYTES",
    "MAX_NATIVE_QUALIFICATION_SOURCE_TOTAL_BYTES",
    "MAX_NATIVE_QUALIFICATION_TRACKED_TREE_FILES",
    "MAX_NATIVE_QUALIFICATION_TRACKED_TREE_MANIFEST_BYTES",
    "MAX_NATIVE_QUALIFICATION_TRACKED_TREE_TOTAL_BYTES",
    "NATIVE_QUALIFICATION_BPE_DISTRIBUTION_VERSION",
    "NATIVE_QUALIFICATION_BPE_SOURCE_PATHS",
    "NATIVE_QUALIFICATION_BUILT_WHEEL_FILENAME",
    "NATIVE_QUALIFICATION_BUILT_WHEEL_PATH",
    "NATIVE_QUALIFICATION_CASES",
    "NATIVE_QUALIFICATION_CASE_SET_DOMAIN",
    "NATIVE_QUALIFICATION_CASE_SET_ID",
    "NATIVE_QUALIFICATION_CASE_SET_SHA256",
    "NATIVE_QUALIFICATION_CONTEXT_DOMAIN",
    "NATIVE_QUALIFICATION_DOMAIN",
    "NATIVE_QUALIFICATION_FAULT_PROFILE_ID",
    "NATIVE_QUALIFICATION_INVOCATION_DOMAIN",
    "NATIVE_QUALIFICATION_LAUNCHER_PROTOCOL_ID",
    "NATIVE_QUALIFICATION_OUTER_SECCOMP_CONTRACT_SHA256",
    "NATIVE_QUALIFICATION_OUTER_SECCOMP_DOMAIN",
    "NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTIONS",
    "NATIVE_QUALIFICATION_OUTER_SECCOMP_INSTRUCTION_BYTES",
    "NATIVE_QUALIFICATION_PARSER_ID",
    "NATIVE_QUALIFICATION_RUNTIME_DEPENDENCY_DOMAIN",
    "NATIVE_QUALIFICATION_RUNTIME_INSTALLER_PATHS",
    "NATIVE_QUALIFICATION_SOURCE_MANIFEST_DOMAIN",
    "NATIVE_QUALIFICATION_SOURCE_PATHS",
    "NATIVE_QUALIFICATION_TRANSCRIPT_DOMAIN",
    "NATIVE_QUALIFICATION_WHEEL_DIST_INFO_PATHS",
    "LinuxInertLauncherNativeQualificationError",
    "LinuxInertLauncherNativeQualificationReport",
    "NativeQualificationActorCategory",
    "NativeQualificationArtifact",
    "NativeQualificationArtifactDuplicate",
    "NativeQualificationBuildTools",
    "NativeQualificationCase",
    "NativeQualificationCaseCleanup",
    "NativeQualificationCaseName",
    "NativeQualificationContainer",
    "NativeQualificationContainerInvocation",
    "NativeQualificationContextBinding",
    "NativeQualificationFinalization",
    "NativeQualificationHost",
    "NativeQualificationInjection",
    "NativeQualificationMountBinding",
    "NativeQualificationMountPurpose",
    "NativeQualificationNamespaceIdentity",
    "NativeQualificationRuntimeDistribution",
    "NativeQualificationSocketRecord",
    "NativeQualificationSourceFile",
    "NativeQualificationSourceManifest",
    "NativeQualificationSourceRun",
    "NativeQualificationTranscriptProjection",
    "NativeQualificationUpstreamWorkflowRun",
    "build_inert_native_qualification_case",
    "build_inert_native_qualification_source_manifest",
    "canonical_inert_native_qualification_report_bytes",
    "inert_native_qualification_id",
    "native_qualification_commit_bpe_tree_manifest_sha256",
    "native_qualification_context_sha256",
    "native_qualification_github_context_bytes",
    "native_qualification_runtime_dependency_manifest_sha256",
    "replay_inert_native_qualification_case",
    "validate_inert_native_qualification_report",
    "validate_inert_native_qualification_report_bytes",
]
