"""Tamper-evident replay bundles with fail-closed verification and rescoring."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from bpe.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    sha256_bytes,
    strict_json_loads,
)
from bpe.grading import score_evidence
from bpe.models import (
    ArtifactRef,
    EvaluationEvidence,
    Grade,
    ReplayAnchor,
    ReplayManifest,
    RewardPolicy,
    ScoringContract,
)

MAX_REPLAY_MANIFEST_BYTES = 256 * 1024
MAX_REPLAY_JSON_DEPTH = 64
MAX_REPLAY_JSON_NODES = 65_536
MAX_REPLAY_ARTIFACTS = 256
MAX_REPLAY_FILE_BYTES = 16 * 1024 * 1024
MAX_REPLAY_TOTAL_BYTES = 128 * 1024 * 1024

_FIXED_REPLAY_FILES = {
    "manifest.json",
    "evidence.json",
    "contract.json",
    "grade.json",
    "events.jsonl",
    "policy.json",
}


class ReplayError(ValueError):
    """Replay content is incomplete, corrupt, or internally inconsistent."""


@dataclass(frozen=True)
class ReplayReceipt:
    manifest: ReplayManifest
    manifest_sha256: str
    anchor: ReplayAnchor


@dataclass(frozen=True)
class ReplayVerification:
    valid: bool
    anchored: bool
    manifest_sha256: str | None
    errors: tuple[str, ...]
    rescored_grade: Grade | None


@dataclass(frozen=True)
class _FileRecord:
    parent_fd: int
    name: str
    label: str
    metadata: tuple[int, int, int, int, int, int, int]
    content: bytes


@dataclass(frozen=True)
class _DirectoryRecord:
    parent_fd: int
    name: str
    label: str
    descriptor: int
    metadata: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class _LoadedReplay:
    manifest: ReplayManifest
    evidence: EvaluationEvidence
    contract: ScoringContract
    stored_grade: Grade
    stored_policy: RewardPolicy


@dataclass(frozen=True)
class _ReplayInspection:
    verification: ReplayVerification
    loaded: _LoadedReplay | None


@dataclass
class _ReplayWriteLedger:
    """Identities created by one writer, used for final checks and safe rollback."""

    root_files: dict[str, tuple[int, int, int, int, int, int, int]] = field(
        default_factory=dict
    )
    artifact_files: dict[str, tuple[int, int, int, int, int, int, int]] = field(
        default_factory=dict
    )
    artifacts_directory_identity: tuple[int, int] | None = None
    store_directory_identity: tuple[int, int] | None = None


def _stable_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _required_open_flags() -> tuple[int, int, int, int]:
    names = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in names):
        raise ReplayError("secure descriptor-relative replay reads are unavailable")
    return os.O_NOFOLLOW, os.O_DIRECTORY, os.O_CLOEXEC, os.O_NONBLOCK


def _fstat_or_close(descriptor: int, *, label: str) -> os.stat_result:
    """Inspect a newly opened descriptor without leaking it on failure."""

    try:
        return os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise ReplayError(f"cannot inspect opened {label}: {exc}") from exc


def _unlink_file_if_pinned(parent_fd: int, name: str, descriptor: int) -> None:
    """Best-effort cleanup without unlinking a replacement directory entry."""

    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError:
        return
    if (
        (visible.st_dev, visible.st_ino) == (opened.st_dev, opened.st_ino)
        and stat.S_ISREG(visible.st_mode)
        and stat.S_ISREG(opened.st_mode)
    ):
        with suppress(OSError):
            os.unlink(name, dir_fd=parent_fd)


def _rmdir_if_identity(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    """Best-effort removal only while a name still identifies the created directory."""

    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return
    if (visible.st_dev, visible.st_ino) == identity and stat.S_ISDIR(visible.st_mode):
        with suppress(OSError):
            os.rmdir(name, dir_fd=parent_fd)


def _rmdir_private_directory_entry(
    parent_fd: int,
    root_device: int,
    name: str,
) -> None:
    """Best-effort cleanup when creation succeeded but no descriptor was acquired."""

    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return
    if (
        stat.S_ISDIR(visible.st_mode)
        and visible.st_dev == root_device
        and visible.st_uid == os.geteuid()
        and not visible.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _rmdir_if_identity(parent_fd, name, (visible.st_dev, visible.st_ino))


def _write_file_at(
    parent_fd: int,
    root_device: int,
    name: str,
    content: bytes,
    *,
    label: str,
) -> _FileRecord:
    """Create one private replay file through its pinned parent descriptor."""

    nofollow, _, cloexec, nonblock = _required_open_flags()
    descriptor = -1
    completed = False
    created_metadata: tuple[int, int, int, int, int, int, int] | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | nofollow
            | cloexec
            | nonblock,
            0o600,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_nlink != 1
        ):
            raise ReplayError(f"{label} is not a private same-device regular file")
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short write while creating replay content")
            written += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != root_device
            or after.st_nlink != 1
            or after.st_size != len(content)
        ):
            raise ReplayError(f"{label} changed while it was being written")
        created_metadata = _stable_metadata(after)
        completed = True
    except FileExistsError as exc:
        raise ReplayError(f"{label} already exists") from exc
    except ReplayError:
        raise
    except OSError as exc:
        raise ReplayError(f"cannot create {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            if not completed:
                _unlink_file_if_pinned(parent_fd, name, descriptor)
            os.close(descriptor)

    try:
        record = _read_file_at(
            name,
            parent_fd=parent_fd,
            root_device=root_device,
            max_bytes=len(content),
            expected_bytes=len(content),
            label=label,
        )
        if record.content != content:
            raise ReplayError(f"{label} differs from the bytes supplied to the writer")
        os.fsync(parent_fd)
        return record
    except BaseException:
        if created_metadata is not None:
            _unlink_if_recorded(parent_fd, name, created_metadata)
        raise


def _ref(content: bytes, media_type: str) -> ArtifactRef:
    return ArtifactRef(sha256=sha256_bytes(content), size_bytes=len(content), media_type=media_type)


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


def _evidence_artifact_refs(evidence: EvaluationEvidence) -> tuple[ArtifactRef, ...]:
    refs: list[ArtifactRef] = [evidence.request.candidate]
    refs.extend(evidence.observation_artifacts.values())
    for stage in evidence.stages:
        refs.extend(stage.artifacts.values())
        for check in stage.checks:
            refs.extend(check.artifacts.values())
    return tuple(refs)


def _artifact_reference_for_content(
    content: bytes,
    evidence_refs: Iterable[ArtifactRef],
) -> ArtifactRef:
    digest = sha256_bytes(content)
    matching = {ref for ref in evidence_refs if ref.sha256 == digest}
    if not matching:
        return ArtifactRef(
            sha256=digest,
            size_bytes=len(content),
            media_type="application/octet-stream",
        )
    if len(matching) != 1:
        raise ReplayError(f"evidence uses inconsistent metadata for artifact {digest}")
    reference = next(iter(matching))
    if reference.size_bytes != len(content):
        raise ReplayError(f"evidence artifact size does not match supplied bytes: {digest}")
    return reference


def _snapshot_artifacts(artifacts: Mapping[str, bytes]) -> dict[str, bytes]:
    try:
        items = tuple(islice(iter(artifacts.items()), MAX_REPLAY_ARTIFACTS + 1))
    except Exception as exc:
        raise ReplayError(f"cannot snapshot replay artifacts: {exc}") from exc
    if len(items) > MAX_REPLAY_ARTIFACTS:
        raise ReplayError(
            f"replay artifacts exceed the {MAX_REPLAY_ARTIFACTS}-artifact limit"
        )

    snapshot: dict[str, bytes] = {}
    total_bytes = 0
    for item in items:
        try:
            logical_name, content = item
        except (TypeError, ValueError) as exc:
            raise ReplayError("replay artifact entries must be key/value pairs") from exc
        if type(logical_name) is not str:
            raise ReplayError("replay artifact names must be plain strings")
        if logical_name in snapshot:
            raise ReplayError(f"replay artifact name is duplicated: {logical_name}")
        if type(content) is not bytes:
            raise ReplayError(f"replay artifact {logical_name} must be immutable bytes")
        if len(content) > MAX_REPLAY_FILE_BYTES:
            raise ReplayError(
                f"replay artifact {logical_name} exceeds the "
                f"{MAX_REPLAY_FILE_BYTES}-byte limit"
            )
        total_bytes += len(content)
        if total_bytes > MAX_REPLAY_TOTAL_BYTES:
            raise ReplayError(
                f"replay artifacts exceed the {MAX_REPLAY_TOTAL_BYTES}-byte total limit"
            )
        snapshot[logical_name] = content
    return snapshot


def _validate_manifest_bounds(manifest: ReplayManifest, manifest_size: int) -> None:
    if manifest_size > MAX_REPLAY_MANIFEST_BYTES:
        raise ReplayError(
            f"replay manifest exceeds the {MAX_REPLAY_MANIFEST_BYTES}-byte limit"
        )
    if len(manifest.artifacts) > MAX_REPLAY_ARTIFACTS:
        raise ReplayError(
            f"replay manifest exceeds the {MAX_REPLAY_ARTIFACTS}-artifact limit"
        )

    fixed_refs = (
        ("evidence", manifest.evidence),
        ("contract", manifest.contract),
        ("grade", manifest.grade),
        ("events", manifest.events),
        ("policy", manifest.policy),
    )
    for label, reference in fixed_refs:
        if reference.size_bytes > MAX_REPLAY_FILE_BYTES:
            raise ReplayError(
                f"{label} exceeds the {MAX_REPLAY_FILE_BYTES}-byte replay file limit"
            )

    reference_by_digest: dict[str, ArtifactRef] = {}
    reference_labels: dict[str, str] = {}
    for label, reference in fixed_refs:
        previous = reference_by_digest.setdefault(reference.sha256, reference)
        if previous != reference:
            raise ReplayError(
                "replay manifest uses inconsistent metadata for digest "
                f"{reference.sha256} between {reference_labels[reference.sha256]} "
                f"and {label}"
            )
        reference_labels.setdefault(reference.sha256, label)
    artifact_by_digest: dict[str, ArtifactRef] = {}
    for logical_name, reference in manifest.artifacts.items():
        if reference.size_bytes > MAX_REPLAY_FILE_BYTES:
            raise ReplayError(
                f"artifact {logical_name} exceeds the "
                f"{MAX_REPLAY_FILE_BYTES}-byte replay file limit"
            )
        previous = reference_by_digest.setdefault(reference.sha256, reference)
        if previous != reference:
            raise ReplayError(
                "replay manifest uses inconsistent metadata for digest "
                f"{reference.sha256} between {reference_labels[reference.sha256]} "
                f"and artifact {logical_name}"
            )
        reference_labels.setdefault(reference.sha256, f"artifact {logical_name}")
        artifact_by_digest.setdefault(reference.sha256, reference)

    total = manifest_size
    total += sum(reference.size_bytes for _, reference in fixed_refs)
    total += sum(reference.size_bytes for reference in artifact_by_digest.values())
    if total > MAX_REPLAY_TOTAL_BYTES:
        raise ReplayError(
            f"replay content exceeds the {MAX_REPLAY_TOTAL_BYTES}-byte total limit"
        )


def validate_replay_manifest(manifest: ReplayManifest) -> ReplayManifest:
    """Validate bounded manifest structure without claiming that referenced bytes exist."""

    try:
        frozen = ReplayManifest.model_validate(manifest.model_dump(mode="python"))
        raw = canonical_json_bytes(frozen)
        _validate_manifest_bounds(frozen, len(raw))
    except ReplayError:
        raise
    except (CanonicalJSONError, ValidationError, ValueError) as exc:
        raise ReplayError(f"invalid replay manifest: {exc}") from exc
    return frozen


def _create_directory_at(
    parent_fd: int,
    root_device: int,
    name: str,
    *,
    label: str,
) -> _DirectoryRecord:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise ReplayError(f"{label} already exists") from exc
    except OSError as exc:
        raise ReplayError(f"cannot create {label}: {exc}") from exc
    descriptor = -1
    completed = False
    try:
        parent_after_create = _stable_metadata(os.fstat(parent_fd))
        descriptor = os.open(
            name,
            os.O_RDONLY | nofollow | directory | cloexec,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ReplayError(f"{label} is not a private same-device directory")
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _stable_metadata(visible) != _stable_metadata(opened):
            raise ReplayError(f"newly created {label} changed while it was being opened")
        if _stable_metadata(os.fstat(parent_fd)) != parent_after_create:
            raise ReplayError(f"parent changed while creating {label}")
        record = _DirectoryRecord(
            parent_fd=parent_fd,
            name=name,
            label=label,
            descriptor=descriptor,
            metadata=_stable_metadata(opened),
        )
        completed = True
        descriptor = -1
        return record
    except OSError as exc:
        raise ReplayError(f"cannot inspect newly created {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            _rmdir_if_pinned(parent_fd, name, descriptor)
            os.close(descriptor)
        elif not completed:
            _rmdir_private_directory_entry(parent_fd, root_device, name)


def _write_replay_tree(
    root_fd: int,
    root_device: int,
    *,
    ledger: _ReplayWriteLedger,
    evidence: EvaluationEvidence,
    contract: ScoringContract,
    grade: Grade,
    policy: RewardPolicy,
    artifacts: Mapping[str, bytes],
) -> ReplayReceipt:
    evidence_bytes = canonical_json_bytes(evidence)
    contract_bytes = canonical_json_bytes(contract)
    grade_bytes = canonical_json_bytes(grade)
    policy_bytes = canonical_json_bytes(policy)
    events_bytes = _event_bytes(evidence)
    evidence_refs = _evidence_artifact_refs(evidence)
    artifact_refs: dict[str, ArtifactRef] = {}
    physical_artifacts: dict[str, bytes] = {}
    for logical_name, content in sorted(artifacts.items()):
        reference = _artifact_reference_for_content(content, evidence_refs)
        prior = physical_artifacts.setdefault(reference.sha256, content)
        if prior != content:
            raise ReplayError(
                f"different artifact bytes claim the same digest: {reference.sha256}"
            )
        artifact_refs[logical_name] = reference

    stored_refs = set(artifact_refs.values())
    missing = set(evidence_refs) - stored_refs
    if missing:
        raise ReplayError(
            "replay is missing evidence artifacts: "
            + ", ".join(sorted(reference.sha256 for reference in missing))
        )

    manifest = ReplayManifest(
        evidence=_ref(evidence_bytes, "application/json"),
        contract=_ref(contract_bytes, "application/json"),
        grade=_ref(grade_bytes, "application/json"),
        events=_ref(events_bytes, "application/x-ndjson"),
        policy=_ref(policy_bytes, "application/json"),
        artifacts=artifact_refs,
    )
    manifest_bytes = canonical_json_bytes(manifest)
    _validate_manifest_bounds(manifest, len(manifest_bytes))

    artifacts_record: _DirectoryRecord | None = None
    store_record: _DirectoryRecord | None = None
    try:
        if physical_artifacts:
            artifacts_record = _create_directory_at(
                root_fd,
                root_device,
                "artifacts",
                label="replay artifact store parent",
            )
            ledger.artifacts_directory_identity = artifacts_record.metadata[:2]
            store_record = _create_directory_at(
                artifacts_record.descriptor,
                root_device,
                "sha256",
                label="replay artifact store",
            )
            ledger.store_directory_identity = store_record.metadata[:2]
            for digest, content in sorted(physical_artifacts.items()):
                record = _write_file_at(
                    store_record.descriptor,
                    root_device,
                    digest,
                    content,
                    label=f"replay artifact {digest}",
                )
                ledger.artifact_files[digest] = record.metadata
            os.fsync(store_record.descriptor)
            os.fsync(artifacts_record.descriptor)

        for name, label, content in (
            ("evidence.json", "replay evidence", evidence_bytes),
            ("contract.json", "replay contract", contract_bytes),
            ("grade.json", "replay grade", grade_bytes),
            ("events.jsonl", "replay events", events_bytes),
            ("policy.json", "replay policy", policy_bytes),
        ):
            record = _write_file_at(
                root_fd,
                root_device,
                name,
                content,
                label=label,
            )
            ledger.root_files[name] = record.metadata
        # The manifest is the readiness marker and is created last.
        manifest_record = _write_file_at(
            root_fd,
            root_device,
            "manifest.json",
            manifest_bytes,
            label="replay manifest",
        )
        ledger.root_files["manifest.json"] = manifest_record.metadata
        os.fsync(root_fd)
    finally:
        if store_record is not None:
            os.close(store_record.descriptor)
        if artifacts_record is not None:
            os.close(artifacts_record.descriptor)
    return ReplayReceipt(
        manifest=manifest,
        manifest_sha256=sha256_bytes(manifest_bytes),
        anchor=ReplayAnchor(
            manifest_sha256=sha256_bytes(manifest_bytes),
            evidence_sha256=sha256_bytes(evidence_bytes),
            grade_sha256=sha256_bytes(grade_bytes),
            contract_sha256=sha256_bytes(contract_bytes),
            policy_sha256=sha256_bytes(policy_bytes),
        ),
    )


def _open_root(root: Path) -> tuple[int, int, tuple[int, int, int, int, int, int, int]]:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before = root.lstat()
    except OSError as exc:
        raise ReplayError(f"cannot inspect replay root: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ReplayError("replay root is missing, not a directory, or a symlink")
    try:
        descriptor = os.open(root, os.O_RDONLY | nofollow | directory | cloexec)
    except OSError as exc:
        raise ReplayError(f"cannot open replay root: {exc}") from exc
    opened = _fstat_or_close(descriptor, label="replay root")
    if _stable_metadata(opened) != _stable_metadata(before) or not stat.S_ISDIR(
        opened.st_mode
    ):
        os.close(descriptor)
        raise ReplayError("replay root changed while it was being opened")
    return descriptor, opened.st_dev, _stable_metadata(opened)


def _open_directory(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    label: str,
) -> _DirectoryRecord:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ReplayError(f"{label}: missing") from exc
    except OSError as exc:
        raise ReplayError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_dev != root_device
    ):
        raise ReplayError(f"{label} is not a same-device non-symlink directory")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | nofollow | directory | cloexec,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ReplayError(f"cannot open {label}: {exc}") from exc
    opened = _fstat_or_close(descriptor, label=label)
    if (
        _stable_metadata(opened) != _stable_metadata(before)
        or not stat.S_ISDIR(opened.st_mode)
        or opened.st_dev != root_device
    ):
        os.close(descriptor)
        raise ReplayError(f"{label} changed while it was being opened")
    return _DirectoryRecord(
        parent_fd=parent_fd,
        name=name,
        label=label,
        descriptor=descriptor,
        metadata=_stable_metadata(opened),
    )


def _read_file_at(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    max_bytes: int,
    label: str,
    expected_bytes: int | None = None,
) -> _FileRecord:
    nofollow, _, cloexec, nonblock = _required_open_flags()
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ReplayError(f"{label}: missing") from exc
    except OSError as exc:
        raise ReplayError(f"cannot inspect {label}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_dev != root_device
    ):
        raise ReplayError(f"{label} is not a same-device non-symlink regular file")
    if before.st_nlink != 1:
        raise ReplayError(f"{label} must not be externally hard-linked")
    if before.st_size > max_bytes:
        raise ReplayError(f"{label} exceeds the {max_bytes}-byte limit")
    if expected_bytes is not None and before.st_size != expected_bytes:
        raise ReplayError(
            f"{label}: integrity mismatch; expected {expected_bytes} bytes, "
            f"got {before.st_size}"
        )
    try:
        # A checked regular file can be replaced by a FIFO before openat(). Nonblocking
        # mode prevents an indefinite wait; the post-open fstat then rejects the swap.
        descriptor = os.open(
            name,
            os.O_RDONLY | nofollow | cloexec | nonblock,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ReplayError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            _stable_metadata(opened) != _stable_metadata(before)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_nlink != 1
        ):
            raise ReplayError(f"{label} changed while it was being opened")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        if len(content) > max_bytes:
            raise ReplayError(f"{label} exceeds the {max_bytes}-byte limit")
        if expected_bytes is not None and len(content) != expected_bytes:
            raise ReplayError(
                f"{label}: integrity mismatch; expected {expected_bytes} bytes, "
                f"got {len(content)}"
            )
        if len(content) != opened.st_size or _stable_metadata(after) != _stable_metadata(
            opened
        ):
            raise ReplayError(f"{label} changed while it was being read")
        return _FileRecord(
            parent_fd=parent_fd,
            name=name,
            label=label,
            metadata=_stable_metadata(after),
            content=content,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _directory_entries(descriptor: int, *, label: str, max_entries: int) -> set[str]:
    entries: set[str] = set()
    count = 0
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                count += 1
                if count > max_entries:
                    raise ReplayError(
                        f"{label} is not closed: exceeds the {max_entries}-entry limit"
                    )
                entries.add(entry.name)
    except ReplayError:
        raise
    except OSError as exc:
        raise ReplayError(f"cannot enumerate {label}: {exc}") from exc
    return entries


def _validate_json_complexity(value: object, *, label: str) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_REPLAY_JSON_DEPTH or nodes > MAX_REPLAY_JSON_NODES:
            raise ReplayError(f"{label} JSON exceeds the structural complexity limit")
        if isinstance(current, dict):
            for key, child in current.items():
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise ReplayError(
                        f"cannot encode canonical JSON in {label}: "
                        "keys must use Unicode scalar values"
                    )
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise ReplayError(
                f"cannot encode canonical JSON in {label}: "
                "strings must use Unicode scalar values"
            )


ModelT = TypeVar("ModelT", bound=BaseModel)


def _parse_canonical_model(raw: bytes, name: str, model_type: type[ModelT]) -> ModelT:
    try:
        value = strict_json_loads(raw)
        _validate_json_complexity(value, label=name)
        model = model_type.model_validate(value)
        canonical = canonical_json_bytes(model)
    except ReplayError:
        raise
    except (CanonicalJSONError, ValidationError, ValueError) as exc:
        raise ReplayError(f"invalid JSON metadata in {name}: {exc}") from exc
    if canonical != raw:
        raise ReplayError(f"metadata is not canonical JSON: {name}")
    return model


def _require_ref(record: _FileRecord, expected: ArtifactRef) -> None:
    actual_digest = sha256_bytes(record.content)
    actual_size = len(record.content)
    if actual_digest != expected.sha256 or actual_size != expected.size_bytes:
        raise ReplayError(
            f"{record.label}: integrity mismatch; "
            f"expected {expected.sha256}/{expected.size_bytes}, "
            f"got {actual_digest}/{actual_size}"
        )


def _recheck_file(record: _FileRecord) -> None:
    try:
        visible = os.stat(record.name, dir_fd=record.parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ReplayError(f"{record.label} changed after it was read: {exc}") from exc
    if _stable_metadata(visible) != record.metadata or not stat.S_ISREG(visible.st_mode):
        raise ReplayError(f"{record.label} changed after it was read")


def _recheck_directory(record: _DirectoryRecord) -> None:
    try:
        visible = os.stat(record.name, dir_fd=record.parent_fd, follow_symlinks=False)
        opened = os.fstat(record.descriptor)
    except OSError as exc:
        raise ReplayError(f"{record.label} changed during replay inspection: {exc}") from exc
    if (
        _stable_metadata(visible) != record.metadata
        or _stable_metadata(opened) != record.metadata
        or not stat.S_ISDIR(visible.st_mode)
    ):
        raise ReplayError(f"{record.label} changed during replay inspection")


def _recheck_root(
    root: Path,
    root_fd: int,
    metadata: tuple[int, int, int, int, int, int, int],
) -> None:
    try:
        visible = root.lstat()
        opened = os.fstat(root_fd)
    except OSError as exc:
        raise ReplayError(f"replay root changed during inspection: {exc}") from exc
    if (
        _stable_metadata(visible) != metadata
        or _stable_metadata(opened) != metadata
        or not stat.S_ISDIR(visible.st_mode)
    ):
        raise ReplayError("replay root changed during inspection")


def _artifact_refs_by_digest(manifest: ReplayManifest) -> dict[str, ArtifactRef]:
    result: dict[str, ArtifactRef] = {}
    for reference in manifest.artifacts.values():
        previous = result.setdefault(reference.sha256, reference)
        if previous != reference:
            raise ReplayError(
                "replay manifest uses inconsistent metadata for artifact "
                f"{reference.sha256}"
            )
    return result


def _artifact_label(manifest: ReplayManifest, digest: str) -> str:
    logical_names = sorted(
        name for name, reference in manifest.artifacts.items() if reference.sha256 == digest
    )
    return "artifact " + ", ".join(logical_names)


def _inspect_replay(
    run_dir: Path,
    *,
    expected_manifest_sha256: str | None,
) -> _ReplayInspection:
    root = run_dir.absolute()
    root_fd = -1
    root_device = -1
    root_metadata: tuple[int, int, int, int, int, int, int] | None = None
    artifacts_record: _DirectoryRecord | None = None
    store_record: _DirectoryRecord | None = None
    file_records: list[_FileRecord] = []
    manifest_digest: str | None = None
    anchored = False
    errors: list[str] = []
    loaded: _LoadedReplay | None = None
    rescored: Grade | None = None

    try:
        root_fd, root_device, root_metadata = _open_root(root)
        manifest_record = _read_file_at(
            "manifest.json",
            parent_fd=root_fd,
            root_device=root_device,
            max_bytes=MAX_REPLAY_MANIFEST_BYTES,
            label="manifest",
        )
        file_records.append(manifest_record)
        manifest_digest = sha256_bytes(manifest_record.content)
        anchored = (
            expected_manifest_sha256 is not None
            and manifest_digest == expected_manifest_sha256
        )
        if expected_manifest_sha256 is not None and not anchored:
            errors.append(
                "manifest trust anchor mismatch: "
                f"expected {expected_manifest_sha256}, got {manifest_digest}"
            )
        manifest = _parse_canonical_model(
            manifest_record.content,
            "manifest.json",
            ReplayManifest,
        )
        _validate_manifest_bounds(manifest, len(manifest_record.content))

        expected_top = set(_FIXED_REPLAY_FILES)
        if manifest.artifacts:
            expected_top.add("artifacts")
        actual_top = _directory_entries(
            root_fd,
            label="replay root",
            max_entries=len(expected_top),
        )
        if actual_top != expected_top:
            missing_top = expected_top - actual_top
            missing_labels = {
                "manifest.json": "manifest",
                "evidence.json": "evidence",
                "contract.json": "contract",
                "grade.json": "grade",
                "events.jsonl": "events",
                "policy.json": "policy",
                "artifacts": "artifact store parent",
            }
            missing_detail = "; ".join(
                f"{missing_labels[name]}: missing" for name in sorted(missing_top)
            )
            if missing_detail:
                missing_detail += "; "
            raise ReplayError(
                missing_detail + "replay tree is not closed; "
                f"unexpected={sorted(actual_top - expected_top)}, "
                f"missing={sorted(missing_top)}"
            )

        artifact_refs = _artifact_refs_by_digest(manifest)
        if manifest.artifacts:
            artifacts_record = _open_directory(
                "artifacts",
                parent_fd=root_fd,
                root_device=root_device,
                label="artifact store parent",
            )
            artifact_children = _directory_entries(
                artifacts_record.descriptor,
                label="artifact store parent",
                max_entries=1,
            )
            if artifact_children != {"sha256"}:
                raise ReplayError(
                    "artifact store parent is not closed; "
                    f"entries={sorted(artifact_children)}"
                )
            store_record = _open_directory(
                "sha256",
                parent_fd=artifacts_record.descriptor,
                root_device=root_device,
                label="artifact store",
            )
            actual_artifacts = _directory_entries(
                store_record.descriptor,
                label="artifact store",
                max_entries=len(artifact_refs),
            )
            if actual_artifacts != set(artifact_refs):
                missing_artifacts = set(artifact_refs) - actual_artifacts
                missing_detail = "; ".join(
                    f"{_artifact_label(manifest, digest)}: missing"
                    for digest in sorted(missing_artifacts)
                )
                if missing_detail:
                    missing_detail += "; "
                raise ReplayError(
                    missing_detail + "artifact store is not closed; "
                    f"unexpected={sorted(actual_artifacts - set(artifact_refs))}, "
                    f"missing={sorted(missing_artifacts)}"
                )

        fixed_specs: tuple[tuple[str, str, ArtifactRef], ...] = (
            ("evidence.json", "evidence", manifest.evidence),
            ("contract.json", "contract", manifest.contract),
            ("grade.json", "grade", manifest.grade),
            ("events.jsonl", "events", manifest.events),
            ("policy.json", "policy", manifest.policy),
        )
        fixed_records: dict[str, _FileRecord] = {}
        actual_bytes_read = len(manifest_record.content)
        for name, label, _reference in fixed_specs:
            remaining_bytes = MAX_REPLAY_TOTAL_BYTES - actual_bytes_read
            if remaining_bytes < 0:
                raise ReplayError(
                    f"replay content exceeds the {MAX_REPLAY_TOTAL_BYTES}-byte total limit"
                )
            record = _read_file_at(
                name,
                parent_fd=root_fd,
                root_device=root_device,
                max_bytes=min(MAX_REPLAY_FILE_BYTES, remaining_bytes),
                label=label,
            )
            file_records.append(record)
            fixed_records[name] = record
            actual_bytes_read += len(record.content)

        evidence = _parse_canonical_model(
            fixed_records["evidence.json"].content,
            "evidence.json",
            EvaluationEvidence,
        )
        contract = _parse_canonical_model(
            fixed_records["contract.json"].content,
            "contract.json",
            ScoringContract,
        )
        stored_grade = _parse_canonical_model(
            fixed_records["grade.json"].content,
            "grade.json",
            Grade,
        )
        stored_policy = _parse_canonical_model(
            fixed_records["policy.json"].content,
            "policy.json",
            RewardPolicy,
        )
        for name, _, reference in fixed_specs:
            _require_ref(fixed_records[name], reference)

        if fixed_records["events.jsonl"].content != _event_bytes(evidence):
            raise ReplayError("events do not match evidence-derived canonical events")

        if store_record is not None:
            for digest, reference in sorted(artifact_refs.items()):
                remaining_bytes = MAX_REPLAY_TOTAL_BYTES - actual_bytes_read
                if remaining_bytes < 0:
                    raise ReplayError(
                        "replay content exceeds the "
                        f"{MAX_REPLAY_TOTAL_BYTES}-byte total limit"
                    )
                record = _read_file_at(
                    digest,
                    parent_fd=store_record.descriptor,
                    root_device=root_device,
                    max_bytes=min(MAX_REPLAY_FILE_BYTES, remaining_bytes),
                    expected_bytes=reference.size_bytes,
                    label=_artifact_label(manifest, digest),
                )
                file_records.append(record)
                _require_ref(record, reference)
                actual_bytes_read += len(record.content)

        stored_refs = set(manifest.artifacts.values())
        for reference in _evidence_artifact_refs(evidence):
            if reference not in stored_refs:
                raise ReplayError(
                    "evidence artifact metadata is absent from manifest: "
                    f"{reference.sha256}/{reference.size_bytes}/{reference.media_type}"
                )

        # Re-enumerate and re-stat through the same pinned descriptors. Consumers use
        # only the sealed models above even if the source tree changes after return.
        if _directory_entries(
            root_fd,
            label="replay root",
            max_entries=len(expected_top),
        ) != expected_top:
            raise ReplayError("replay tree changed while it was being inspected")
        if artifacts_record is not None and store_record is not None:
            if _directory_entries(
                artifacts_record.descriptor,
                label="artifact store parent",
                max_entries=1,
            ) != {"sha256"}:
                raise ReplayError("artifact store parent changed during inspection")
            if _directory_entries(
                store_record.descriptor,
                label="artifact store",
                max_entries=len(artifact_refs),
            ) != set(artifact_refs):
                raise ReplayError("artifact store changed during inspection")
        for record in file_records:
            _recheck_file(record)
        if store_record is not None:
            _recheck_directory(store_record)
        if artifacts_record is not None:
            _recheck_directory(artifacts_record)
        _recheck_root(root, root_fd, root_metadata)

        loaded = _LoadedReplay(
            manifest=manifest,
            evidence=evidence,
            contract=contract,
            stored_grade=stored_grade,
            stored_policy=stored_policy,
        )
        try:
            rescored = score_evidence(evidence, contract, stored_policy)
            if rescored != stored_grade:
                errors.append("stored grade does not equal deterministic rescore")
        except (TypeError, ValueError, ValidationError) as exc:
            errors.append(f"replay cannot be rescored: {exc}")
    except (OSError, CanonicalJSONError, ValidationError, ReplayError) as exc:
        errors.append(f"invalid replay: {exc}")
    finally:
        if store_record is not None:
            os.close(store_record.descriptor)
        if artifacts_record is not None:
            os.close(artifacts_record.descriptor)
        if root_fd >= 0:
            os.close(root_fd)

    verification = ReplayVerification(
        valid=not errors,
        anchored=anchored,
        manifest_sha256=manifest_digest,
        errors=tuple(errors),
        rescored_grade=rescored,
    )
    if errors:
        loaded = None
    return _ReplayInspection(verification=verification, loaded=loaded)


def _open_writer_parent(parent: Path) -> tuple[int, int, tuple[int, int, int, int, int, int, int]]:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before = parent.lstat()
    except OSError as exc:
        raise ReplayError(f"cannot inspect replay parent: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReplayError(
            "replay writer requires a caller-owned, non-symlink parent "
            "with no group or other write permission"
        )
    try:
        descriptor = os.open(parent, os.O_RDONLY | nofollow | directory | cloexec)
    except OSError as exc:
        raise ReplayError(f"cannot open replay parent: {exc}") from exc
    opened = _fstat_or_close(descriptor, label="replay parent")
    if _stable_metadata(opened) != _stable_metadata(before):
        os.close(descriptor)
        raise ReplayError("replay parent changed while it was being opened")
    return descriptor, opened.st_dev, _stable_metadata(opened)


def _require_writer_parent(
    parent: Path,
    parent_fd: int,
    metadata: tuple[int, int, int, int, int, int, int],
) -> None:
    try:
        visible = parent.lstat()
        opened = os.fstat(parent_fd)
    except OSError as exc:
        raise ReplayError(f"replay parent changed during publication: {exc}") from exc
    expected_identity = metadata[:3]
    if (
        _stable_metadata(visible)[:3] != expected_identity
        or _stable_metadata(opened)[:3] != expected_identity
        or visible.st_uid != os.geteuid()
        or opened.st_uid != os.geteuid()
        or visible.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReplayError("replay parent changed during publication")


def _reserve_replay_target(
    *,
    parent_fd: int,
    parent_device: int,
    target_name: str,
    target_display: Path,
) -> _DirectoryRecord:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        os.mkdir(target_name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise ReplayError(f"replay target already exists: {target_display}") from exc
    except OSError as exc:
        raise ReplayError(f"cannot reserve replay target {target_display}: {exc}") from exc
    descriptor = -1
    completed = False
    try:
        parent_after_create = _stable_metadata(os.fstat(parent_fd))
        try:
            descriptor = os.open(
                target_name,
                os.O_RDONLY | nofollow | directory | cloexec,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise ReplayError(
                f"cannot open reserved replay target {target_display}: {exc}"
            ) from exc
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != parent_device
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ReplayError(
                "reserved replay target must be a caller-owned, private, "
                "same-device directory"
            )
        try:
            visible = os.stat(
                target_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ReplayError(
                f"cannot inspect reserved replay target {target_display}: {exc}"
            ) from exc
        if _stable_metadata(visible) != _stable_metadata(opened):
            raise ReplayError("reserved replay target changed while it was being opened")
        if _stable_metadata(os.fstat(parent_fd)) != parent_after_create:
            raise ReplayError(
                "replay parent changed while the target was being reserved"
            )
        record = _DirectoryRecord(
            parent_fd=parent_fd,
            name=target_name,
            label="reserved replay target",
            descriptor=descriptor,
            metadata=_stable_metadata(opened),
        )
        completed = True
        descriptor = -1
        return record
    except OSError as exc:
        raise ReplayError(
            f"cannot inspect reserved replay target {target_display}: {exc}"
        ) from exc
    finally:
        if not completed:
            if descriptor >= 0:
                _rmdir_if_pinned(parent_fd, target_name, descriptor)
                os.close(descriptor)
            else:
                _rmdir_private_directory_entry(parent_fd, parent_device, target_name)


def _rmdir_if_pinned(parent_fd: int, name: str, descriptor: int) -> None:
    """Remove one known directory entry only if it still names the pinned inode."""

    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError:
        return
    if (
        (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
        or not stat.S_ISDIR(visible.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
    ):
        return
    with suppress(OSError):
        os.rmdir(name, dir_fd=parent_fd)


def _unlink_if_recorded(
    parent_fd: int,
    name: str,
    metadata: tuple[int, int, int, int, int, int, int],
) -> None:
    """Best-effort unlink only while an entry has the writer-created inode."""

    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return
    if (
        _stable_metadata(visible)[:2] == metadata[:2]
        and stat.S_ISREG(visible.st_mode)
    ):
        with suppress(OSError):
            os.unlink(name, dir_fd=parent_fd)


def _open_recorded_directory(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    expected_identity: tuple[int, int] | None,
    label: str,
) -> _DirectoryRecord | None:
    if expected_identity is None:
        return None
    try:
        record = _open_directory(
            name,
            parent_fd=parent_fd,
            root_device=root_device,
            label=label,
        )
    except ReplayError:
        return None
    if record.metadata[:2] != expected_identity:
        os.close(record.descriptor)
        return None
    return record


def _recheck_written_tree(
    *,
    root_fd: int,
    root_device: int,
    ledger: _ReplayWriteLedger,
) -> None:
    """Recheck the exact entries created by the writer through its pinned root."""

    expected_root = set(ledger.root_files)
    if ledger.artifacts_directory_identity is not None:
        expected_root.add("artifacts")
    if _directory_entries(
        root_fd,
        label="written replay root",
        max_entries=len(expected_root),
    ) != expected_root:
        raise ReplayError("written replay root changed after self-verification")
    for name, metadata in ledger.root_files.items():
        try:
            visible = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            raise ReplayError(
                f"written replay file {name} changed after self-verification: {exc}"
            ) from exc
        if _stable_metadata(visible) != metadata or not stat.S_ISREG(visible.st_mode):
            raise ReplayError(
                f"written replay file {name} changed after self-verification"
            )

    artifacts_record = _open_recorded_directory(
        "artifacts",
        parent_fd=root_fd,
        root_device=root_device,
        expected_identity=ledger.artifacts_directory_identity,
        label="written replay artifact store parent",
    )
    store_record: _DirectoryRecord | None = None
    try:
        if ledger.artifacts_directory_identity is not None and artifacts_record is None:
            raise ReplayError("written replay artifact store parent changed")
        if artifacts_record is None:
            return
        if _directory_entries(
            artifacts_record.descriptor,
            label="written replay artifact store parent",
            max_entries=1,
        ) != {"sha256"}:
            raise ReplayError("written replay artifact store parent changed")
        store_record = _open_recorded_directory(
            "sha256",
            parent_fd=artifacts_record.descriptor,
            root_device=root_device,
            expected_identity=ledger.store_directory_identity,
            label="written replay artifact store",
        )
        if store_record is None:
            raise ReplayError("written replay artifact store changed")
        if _directory_entries(
            store_record.descriptor,
            label="written replay artifact store",
            max_entries=len(ledger.artifact_files),
        ) != set(ledger.artifact_files):
            raise ReplayError("written replay artifact store changed")
        for name, metadata in ledger.artifact_files.items():
            try:
                visible = os.stat(
                    name,
                    dir_fd=store_record.descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ReplayError(
                    f"written replay artifact {name} changed after "
                    f"self-verification: {exc}"
                ) from exc
            if _stable_metadata(visible) != metadata or not stat.S_ISREG(
                visible.st_mode
            ):
                raise ReplayError(
                    f"written replay artifact {name} changed after self-verification"
                )
        _recheck_directory(store_record)
        _recheck_directory(artifacts_record)
    finally:
        if store_record is not None:
            os.close(store_record.descriptor)
        if artifacts_record is not None:
            os.close(artifacts_record.descriptor)


def _discard_owned_replay_tree(
    *,
    parent_fd: int,
    root_device: int,
    root_fd: int,
    root_name: str,
    ledger: _ReplayWriteLedger,
) -> None:
    """Best-effort rollback of recorded identities through pinned descriptors."""

    for name, metadata in ledger.root_files.items():
        _unlink_if_recorded(root_fd, name, metadata)

    artifacts_record = _open_recorded_directory(
        "artifacts",
        parent_fd=root_fd,
        root_device=root_device,
        expected_identity=ledger.artifacts_directory_identity,
        label="rollback artifact store parent",
    )
    store_record: _DirectoryRecord | None = None
    try:
        if artifacts_record is not None:
            store_record = _open_recorded_directory(
                "sha256",
                parent_fd=artifacts_record.descriptor,
                root_device=root_device,
                expected_identity=ledger.store_directory_identity,
                label="rollback artifact store",
            )
            if store_record is not None:
                for name, metadata in ledger.artifact_files.items():
                    _unlink_if_recorded(store_record.descriptor, name, metadata)
                _rmdir_if_pinned(
                    artifacts_record.descriptor,
                    "sha256",
                    store_record.descriptor,
                )
            _rmdir_if_pinned(root_fd, "artifacts", artifacts_record.descriptor)
    finally:
        if store_record is not None:
            os.close(store_record.descriptor)
        if artifacts_record is not None:
            os.close(artifacts_record.descriptor)
        _rmdir_if_pinned(parent_fd, root_name, root_fd)


def write_replay(
    run_dir: Path,
    *,
    evidence: EvaluationEvidence,
    contract: ScoringContract,
    grade: Grade,
    policy: RewardPolicy,
    artifacts: Mapping[str, bytes],
) -> ReplayReceipt:
    """Prepare and verify a replay in a new descriptor-pinned target directory."""

    evidence = EvaluationEvidence.model_validate(evidence.model_dump(mode="python"))
    contract = ScoringContract.model_validate(contract.model_dump(mode="python"))
    policy = RewardPolicy.model_validate(policy.model_dump(mode="python"))
    grade = Grade.model_validate(grade.model_dump(mode="python"))
    if grade != score_evidence(evidence, contract, policy):
        raise ReplayError("grade does not match evidence, contract, and policy")
    artifact_snapshot = _snapshot_artifacts(artifacts)
    ledger = _ReplayWriteLedger()

    target = run_dir.absolute()
    target_name = target.name
    if target_name in {"", ".", ".."}:
        raise ReplayError("replay target must name one directory entry")
    target.parent.mkdir(parents=True, exist_ok=True)

    parent_fd = -1
    parent_device = -1
    target_record: _DirectoryRecord | None = None
    published = False
    try:
        parent_fd, parent_device, parent_metadata = _open_writer_parent(target.parent)
        try:
            os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ReplayError(f"cannot inspect replay target {target}: {exc}") from exc
        else:
            raise ReplayError(f"replay target already exists: {target}")

        target_record = _reserve_replay_target(
            parent_fd=parent_fd,
            parent_device=parent_device,
            target_name=target_name,
            target_display=target,
        )
        receipt = _write_replay_tree(
            target_record.descriptor,
            parent_device,
            ledger=ledger,
            evidence=evidence,
            contract=contract,
            grade=grade,
            policy=policy,
            artifacts=artifact_snapshot,
        )
        target_record = _DirectoryRecord(
            parent_fd=target_record.parent_fd,
            name=target_record.name,
            label=target_record.label,
            descriptor=target_record.descriptor,
            metadata=_stable_metadata(os.fstat(target_record.descriptor)),
        )
        os.fsync(parent_fd)
        _require_writer_parent(target.parent, parent_fd, parent_metadata)
        _recheck_directory(target_record)
        verification = _inspect_replay(
            target,
            expected_manifest_sha256=receipt.manifest_sha256,
        ).verification
        if not verification.valid or not verification.anchored:
            raise ReplayError(
                "published replay failed self-verification: "
                + "; ".join(verification.errors)
            )
        _recheck_written_tree(
            root_fd=target_record.descriptor,
            root_device=parent_device,
            ledger=ledger,
        )
        _require_writer_parent(target.parent, parent_fd, parent_metadata)
        _recheck_directory(target_record)
        published = True
        return receipt
    finally:
        if target_record is not None and not published:
            _discard_owned_replay_tree(
                parent_fd=parent_fd,
                root_device=parent_device,
                root_fd=target_record.descriptor,
                root_name=target_name,
                ledger=ledger,
            )
        if target_record is not None:
            os.close(target_record.descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def verify_replay(
    run_dir: Path,
    *,
    expected_manifest_sha256: str | None = None,
) -> ReplayVerification:
    """Verify one closed replay through descriptor-pinned, bounded reads."""

    return _inspect_replay(
        run_dir,
        expected_manifest_sha256=expected_manifest_sha256,
    ).verification


def rescore_replay(
    run_dir: Path,
    policy: RewardPolicy,
    *,
    expected_manifest_sha256: str | None = None,
) -> Grade:
    """Apply a new reward policy to sealed evidence without rerunning candidate code."""

    inspection = _inspect_replay(
        run_dir,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    if not inspection.verification.valid or inspection.loaded is None:
        raise ReplayError(
            "cannot rescore invalid replay: "
            + "; ".join(inspection.verification.errors)
        )
    validated_policy = RewardPolicy.model_validate(policy.model_dump(mode="python"))
    return score_evidence(
        inspection.loaded.evidence,
        inspection.loaded.contract,
        validated_policy,
    )


__all__ = [
    "MAX_REPLAY_ARTIFACTS",
    "MAX_REPLAY_FILE_BYTES",
    "MAX_REPLAY_JSON_DEPTH",
    "MAX_REPLAY_JSON_NODES",
    "MAX_REPLAY_MANIFEST_BYTES",
    "MAX_REPLAY_TOTAL_BYTES",
    "ReplayError",
    "ReplayReceipt",
    "ReplayVerification",
    "rescore_replay",
    "validate_replay_manifest",
    "verify_replay",
    "write_replay",
]
