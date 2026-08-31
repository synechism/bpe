"""Public/private task loading, hashing, and admission linting."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TypeVar

from pydantic import BaseModel

from bpe.canonical import CanonicalJSONError, sha256_json, strict_json_loads
from bpe.models import (
    ArtifactRef,
    ExpectedCheck,
    FileRef,
    PrivateGrader,
    PublicTask,
    ScoringContract,
    Stage,
)


class TaskBundleError(ValueError):
    """A task bundle is malformed or fails closed on integrity checks."""


MAX_TASK_METADATA_BYTES = 256 * 1024
MAX_TASK_JSON_DEPTH = 64
MAX_TASK_JSON_NODES = 65_536
MAX_TASK_ARTIFACTS = 256
MAX_TASK_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TASK_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TASK_PATH_DEPTH = 32
MAX_TASK_TREE_ENTRIES = 4_096
MAX_TASK_DIRECTORY_ENTRIES = 512
MAX_TASK_LEAKAGE_COMPARISON_WORK = 64 * 1024 * 1024


@dataclass(frozen=True)
class TaskBundle:
    root: Path
    public: PublicTask
    private: PrivateGrader
    public_sha256: str
    private_sha256: str
    bundle_sha256: str
    _artifact_bytes: tuple[tuple[str, str, bytes], ...] = field(
        default=(),
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class LintIssue:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class _ObjectSnapshot:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    links: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _ObjectSnapshot:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
            links=value.st_nlink,
        )


@dataclass(frozen=True)
class _FileRead:
    content: bytes
    sha256: str
    snapshot: _ObjectSnapshot


@dataclass
class _ExpectedTree:
    directories: set[tuple[str, ...]]
    files: dict[tuple[str, ...], FileRef | None]


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _required_open_flags() -> tuple[int, int, int, int]:
    names = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in names):
        raise TaskBundleError("secure descriptor-relative task reads are unavailable")
    return os.O_NOFOLLOW, os.O_DIRECTORY, os.O_CLOEXEC, os.O_NONBLOCK


def _fstat_or_close(descriptor: int, *, label: str) -> _ObjectSnapshot:
    try:
        return _ObjectSnapshot.from_stat(os.fstat(descriptor))
    except OSError as exc:
        with suppress(OSError):
            os.close(descriptor)
        raise TaskBundleError(f"cannot inspect opened {label}: {exc}") from exc


def _snapshot_matches(left: _ObjectSnapshot, right: _ObjectSnapshot) -> bool:
    return left == right


def _open_root(root: Path) -> tuple[int, _ObjectSnapshot]:
    nofollow, directory, cloexec, _ = _required_open_flags()
    try:
        before_stat = root.lstat()
    except OSError as exc:
        raise TaskBundleError(f"cannot inspect task bundle root: {exc}") from exc
    before = _ObjectSnapshot.from_stat(before_stat)
    if stat.S_ISLNK(before.mode) or not stat.S_ISDIR(before.mode):
        raise TaskBundleError("task bundle root is not a non-symlink directory")
    try:
        descriptor = os.open(root, os.O_RDONLY | nofollow | directory | cloexec)
    except OSError as exc:
        raise TaskBundleError(f"cannot open task bundle root: {exc}") from exc
    opened = _fstat_or_close(descriptor, label="task bundle root")
    if not _snapshot_matches(opened, before) or not stat.S_ISDIR(opened.mode):
        os.close(descriptor)
        raise TaskBundleError("task bundle root changed while it was being opened")
    return descriptor, opened


def _open_component(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    directory: bool,
    label: str,
) -> tuple[int, _ObjectSnapshot]:
    nofollow, directory_flag, cloexec, nonblock = _required_open_flags()
    try:
        before_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise TaskBundleError(f"cannot inspect {label}: {exc}") from exc
    before = _ObjectSnapshot.from_stat(before_stat)
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    kind = "directory" if directory else "regular file"
    if (
        stat.S_ISLNK(before.mode)
        or not expected_kind(before.mode)
        or before.device != root_device
    ):
        raise TaskBundleError(f"{label} is not a same-device non-symlink {kind}")
    if not directory and before.links != 1:
        raise TaskBundleError(f"{label} must not be externally hard-linked")

    flags = os.O_RDONLY | nofollow | cloexec
    if directory:
        flags |= directory_flag
    else:
        # If an attacker swaps a checked regular file for a FIFO before openat(),
        # O_NONBLOCK keeps the verifier from hanging before the post-open fstat rejects it.
        flags |= nonblock
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise TaskBundleError(f"cannot open {label}: {exc}") from exc
    opened = _fstat_or_close(descriptor, label=label)
    if (
        not _snapshot_matches(opened, before)
        or not expected_kind(opened.mode)
        or opened.device != root_device
        or (not directory and opened.links != 1)
    ):
        os.close(descriptor)
        raise TaskBundleError(f"{label} changed while it was being opened")
    return descriptor, opened


def _verify_snapshot_at(
    name: str,
    *,
    parent_fd: int,
    expected: _ObjectSnapshot,
    directory: bool,
    label: str,
) -> None:
    try:
        current_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise TaskBundleError(f"cannot re-inspect {label}: {exc}") from exc
    current = _ObjectSnapshot.from_stat(current_stat)
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not _snapshot_matches(current, expected)
        or not expected_kind(current.mode)
        or stat.S_ISLNK(current.mode)
        or (not directory and current.links != 1)
    ):
        raise TaskBundleError(f"{label} changed while the task bundle was being loaded")


def _read_file_at(
    name: str,
    *,
    parent_fd: int,
    root_device: int,
    max_bytes: int,
    label: str,
    expected_bytes: int | None = None,
) -> _FileRead:
    descriptor, opened = _open_component(
        name,
        parent_fd=parent_fd,
        root_device=root_device,
        directory=False,
        label=label,
    )
    try:
        if opened.size > max_bytes:
            raise TaskBundleError(f"{label} exceeds the {max_bytes}-byte limit")
        if expected_bytes is not None and opened.size != expected_bytes:
            raise TaskBundleError(
                f"{label} size mismatch: expected {expected_bytes}, got {opened.size}"
            )

        digest = hashlib.sha256()
        content = bytearray()
        while len(content) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            digest.update(chunk)
        after = _ObjectSnapshot.from_stat(os.fstat(descriptor))
        if len(content) > max_bytes:
            raise TaskBundleError(f"{label} exceeds the {max_bytes}-byte limit")
        if expected_bytes is not None and len(content) != expected_bytes:
            raise TaskBundleError(
                f"{label} size mismatch: expected {expected_bytes}, got {len(content)}"
            )
        if len(content) != opened.size or not _snapshot_matches(after, opened):
            raise TaskBundleError(f"{label} changed while it was being read")
        return _FileRead(bytes(content), digest.hexdigest(), opened)
    finally:
        os.close(descriptor)


def _directory_entries(
    descriptor: int,
    *,
    label: str,
    max_entries: int,
) -> set[str]:
    entries: set[str] = set()
    count = 0
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                count += 1
                if count > max_entries:
                    raise TaskBundleError(
                        f"{label} exceeds the {max_entries}-entry limit"
                    )
                entries.add(entry.name)
    except TaskBundleError:
        raise
    except OSError as exc:
        raise TaskBundleError(f"cannot enumerate {label}: {exc}") from exc
    if len(entries) != count or any(not isinstance(name, str) for name in entries):
        raise TaskBundleError(f"{label} contains invalid directory entries")
    return entries


def _validate_json_complexity(value: object, *, label: str) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_TASK_JSON_DEPTH or nodes > MAX_TASK_JSON_NODES:
            raise TaskBundleError(f"{label} exceeds the JSON structural complexity limit")
        if isinstance(current, dict):
            for key, child in current.items():
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise TaskBundleError(f"{label} keys must use Unicode scalar values")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise TaskBundleError(f"{label} strings must use Unicode scalar values")


def _read_model_bytes(raw: bytes, model_type: type[_ModelT], *, label: str) -> _ModelT:
    # Task metadata has historically been checked in as pretty-printed JSON.  Preserve
    # that accepted source format, while parsing strict JSON and hashing only the
    # validated model's canonical representation.
    try:
        value = strict_json_loads(raw)
        _validate_json_complexity(value, label=label)
        return model_type.model_validate(value)
    except TaskBundleError:
        raise
    except (CanonicalJSONError, ValueError) as exc:
        raise TaskBundleError(f"invalid {label}: {exc}") from exc


def _file_refs(model: BaseModel) -> Iterable[FileRef]:
    def walk(value: object) -> Iterable[FileRef]:
        if isinstance(value, FileRef):
            yield value
        elif isinstance(value, BaseModel):
            for child in value.__dict__.values():
                yield from walk(child)
        elif isinstance(value, dict):
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, (tuple, list)):
            for child in value:
                yield from walk(child)

    yield from walk(model)


def _expected_tree(
    metadata_name: str,
    refs: tuple[FileRef, ...],
    *,
    artifact_byte_budget: int,
) -> _ExpectedTree:
    if len(refs) > MAX_TASK_ARTIFACTS:
        raise TaskBundleError(
            f"task projection exceeds the {MAX_TASK_ARTIFACTS}-artifact limit"
        )

    directories: set[tuple[str, ...]] = {()}
    files: dict[tuple[str, ...], FileRef | None] = {(metadata_name,): None}
    for ref in refs:
        parts = PurePosixPath(ref.path).parts
        if not parts or len(parts) > MAX_TASK_PATH_DEPTH:
            raise TaskBundleError(
                f"artifact path exceeds the {MAX_TASK_PATH_DEPTH}-component limit: {ref.path}"
            )
        if any("\x00" in component for component in parts):
            raise TaskBundleError(f"artifact path contains a null byte: {ref.path}")
        for depth in range(1, len(parts)):
            directory = parts[:depth]
            if directory in files:
                raise TaskBundleError(f"artifact path conflicts with a file: {ref.path}")
            directories.add(directory)
        path = tuple(parts)
        if path in directories or path == (metadata_name,):
            raise TaskBundleError(f"artifact path conflicts with task metadata: {ref.path}")
        previous = files.get(path)
        if previous is not None and previous != ref:
            raise TaskBundleError(f"artifact path has inconsistent identities: {ref.path}")
        files[path] = ref

    tree_entries = len(directories) - 1 + len(files)
    if tree_entries > MAX_TASK_TREE_ENTRIES:
        raise TaskBundleError(
            f"task projection exceeds the {MAX_TASK_TREE_ENTRIES}-entry tree limit"
        )
    unique_refs = tuple(ref for ref in files.values() if ref is not None)
    for ref in unique_refs:
        if ref.size_bytes > MAX_TASK_ARTIFACT_BYTES:
            raise TaskBundleError(
                f"artifact {ref.path} exceeds the {MAX_TASK_ARTIFACT_BYTES}-byte limit"
            )
    total_bytes = sum(ref.size_bytes for ref in unique_refs)
    if total_bytes > artifact_byte_budget:
        raise TaskBundleError(
            f"task projection exceeds its {artifact_byte_budget}-byte artifact limit"
        )
    return _ExpectedTree(directories=directories, files=files)


def _children_at(
    tree: _ExpectedTree,
    path: tuple[str, ...],
) -> tuple[set[str], dict[str, FileRef | None]]:
    child_directories = {
        candidate[-1]
        for candidate in tree.directories
        if len(candidate) == len(path) + 1 and candidate[:-1] == path
    }
    child_files = {
        candidate[-1]: ref
        for candidate, ref in tree.files.items()
        if len(candidate) == len(path) + 1 and candidate[:-1] == path
    }
    return child_directories, child_files


def _load_tree_directory(
    *,
    directory_fd: int,
    directory_path: tuple[str, ...],
    root_device: int,
    tree: _ExpectedTree,
    metadata_name: str,
    metadata_read: _FileRead,
    artifact_bytes: dict[str, bytes],
) -> None:
    child_directories, child_files = _children_at(tree, directory_path)
    expected_entries = child_directories | set(child_files)
    label_path = "/".join(directory_path) or "projection root"
    actual_entries = _directory_entries(
        directory_fd,
        label=f"task {label_path}",
        max_entries=MAX_TASK_DIRECTORY_ENTRIES,
    )
    if actual_entries != expected_entries:
        unreferenced = actual_entries - expected_entries
        unreferenced_directories: list[str] = []
        for name in sorted(unreferenced):
            try:
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(entry.st_mode) and not stat.S_ISLNK(entry.st_mode):
                unreferenced_directories.append(name)
        raise TaskBundleError(
            "task tree is not closed; "
            f"at={label_path}, unreferenced={sorted(unreferenced)}, "
            f"missing={sorted(expected_entries - actual_entries)}, "
            f"unreferenced_directories={unreferenced_directories}"
        )

    file_snapshots: dict[str, _ObjectSnapshot] = {}
    for name, ref in sorted(child_files.items()):
        path = (*directory_path, name)
        display_path = "/".join(path)
        if not directory_path and name == metadata_name:
            file_snapshots[name] = metadata_read.snapshot
            continue
        if ref is None:
            raise TaskBundleError(f"task metadata appears at an invalid path: {display_path}")
        artifact = _read_file_at(
            name,
            parent_fd=directory_fd,
            root_device=root_device,
            max_bytes=MAX_TASK_ARTIFACT_BYTES,
            label=f"task artifact {display_path}",
        )
        file_snapshots[name] = artifact.snapshot
        if (artifact.sha256, len(artifact.content)) != (ref.sha256, ref.size_bytes):
            raise TaskBundleError(
                f"artifact integrity mismatch for {ref.path}: expected "
                f"{ref.sha256}/{ref.size_bytes}, got {artifact.sha256}/{len(artifact.content)}"
            )
        artifact_bytes[ref.path] = artifact.content

    directory_snapshots: dict[str, _ObjectSnapshot] = {}
    for name in sorted(child_directories):
        child_path = (*directory_path, name)
        display_path = "/".join(child_path)
        child_fd, child_snapshot = _open_component(
            name,
            parent_fd=directory_fd,
            root_device=root_device,
            directory=True,
            label=f"task directory {display_path}",
        )
        directory_snapshots[name] = child_snapshot
        try:
            _load_tree_directory(
                directory_fd=child_fd,
                directory_path=child_path,
                root_device=root_device,
                tree=tree,
                metadata_name=metadata_name,
                metadata_read=metadata_read,
                artifact_bytes=artifact_bytes,
            )
        finally:
            os.close(child_fd)

    for name, snapshot in file_snapshots.items():
        _verify_snapshot_at(
            name,
            parent_fd=directory_fd,
            expected=snapshot,
            directory=False,
            label=f"task file {'/'.join((*directory_path, name))}",
        )
    for name, snapshot in directory_snapshots.items():
        _verify_snapshot_at(
            name,
            parent_fd=directory_fd,
            expected=snapshot,
            directory=True,
            label=f"task directory {'/'.join((*directory_path, name))}",
        )
    if (
        _directory_entries(
            directory_fd,
            label=f"task {label_path}",
            max_entries=MAX_TASK_DIRECTORY_ENTRIES,
        )
        != expected_entries
    ):
        raise TaskBundleError(f"task {label_path} changed while it was being loaded")


def _load_projection(
    *,
    projection_fd: int,
    root_device: int,
    metadata_name: str,
    model_type: type[_ModelT],
    projection_name: str,
    artifact_byte_budget: int,
) -> tuple[_ModelT, tuple[tuple[str, bytes], ...]]:
    metadata = _read_file_at(
        metadata_name,
        parent_fd=projection_fd,
        root_device=root_device,
        max_bytes=MAX_TASK_METADATA_BYTES,
        label=f"{projection_name} task metadata",
    )
    model = _read_model_bytes(
        metadata.content,
        model_type,
        label=f"{projection_name}/{metadata_name}",
    )
    refs = tuple(_file_refs(model))
    tree = _expected_tree(
        metadata_name,
        refs,
        artifact_byte_budget=artifact_byte_budget,
    )
    artifact_bytes: dict[str, bytes] = {}
    _load_tree_directory(
        directory_fd=projection_fd,
        directory_path=(),
        root_device=root_device,
        tree=tree,
        metadata_name=metadata_name,
        metadata_read=metadata,
        artifact_bytes=artifact_bytes,
    )
    return model, tuple(sorted(artifact_bytes.items()))


def load_task_bundle(root: Path) -> TaskBundle:
    unresolved_root = root.absolute()
    root_fd, root_snapshot = _open_root(unresolved_root)
    public_fd = -1
    private_fd = -1
    try:
        try:
            resolved_root = unresolved_root.resolve(strict=True)
            resolved_snapshot = _ObjectSnapshot.from_stat(resolved_root.stat())
        except OSError as exc:
            raise TaskBundleError(f"cannot resolve task bundle root: {exc}") from exc
        if not _snapshot_matches(resolved_snapshot, root_snapshot):
            raise TaskBundleError("task bundle root changed while it was being resolved")

        if _directory_entries(
            root_fd,
            label="task bundle root",
            max_entries=MAX_TASK_DIRECTORY_ENTRIES,
        ) != {
            "public",
            "grader",
        }:
            raise TaskBundleError("task root must contain exactly public/ and grader/")
        public_fd, public_snapshot = _open_component(
            "public",
            parent_fd=root_fd,
            root_device=root_snapshot.device,
            directory=True,
            label="public task directory",
        )
        private_fd, private_snapshot = _open_component(
            "grader",
            parent_fd=root_fd,
            root_device=root_snapshot.device,
            directory=True,
            label="private grader directory",
        )

        public, public_artifacts = _load_projection(
            projection_fd=public_fd,
            root_device=root_snapshot.device,
            metadata_name="task.json",
            model_type=PublicTask,
            projection_name="public",
            artifact_byte_budget=MAX_TASK_TOTAL_ARTIFACT_BYTES,
        )
        remaining_artifact_bytes = MAX_TASK_TOTAL_ARTIFACT_BYTES - sum(
            len(content) for _, content in public_artifacts
        )
        private, private_artifacts = _load_projection(
            projection_fd=private_fd,
            root_device=root_snapshot.device,
            metadata_name="grader.json",
            model_type=PrivateGrader,
            projection_name="grader",
            artifact_byte_budget=remaining_artifact_bytes,
        )

        if public.task_id != private.task_id or public.version != private.task_version:
            raise TaskBundleError("public and private task identities differ")
        if public.family == "repair" and (
            private.root_cause is None or private.mutation is None
        ):
            raise TaskBundleError("repair tasks require root-cause and mutation metadata")
        if public.family == "generation" and (
            private.root_cause is not None or private.mutation is not None
        ):
            raise TaskBundleError("generation tasks cannot carry repair-mutation metadata")
        if public.environment_id == "":
            raise TaskBundleError("environment ID cannot be empty")

        _verify_snapshot_at(
            "public",
            parent_fd=root_fd,
            expected=public_snapshot,
            directory=True,
            label="public task directory",
        )
        _verify_snapshot_at(
            "grader",
            parent_fd=root_fd,
            expected=private_snapshot,
            directory=True,
            label="private grader directory",
        )
        if _directory_entries(
            root_fd,
            label="task bundle root",
            max_entries=MAX_TASK_DIRECTORY_ENTRIES,
        ) != {
            "public",
            "grader",
        }:
            raise TaskBundleError("task bundle root changed while it was being loaded")
        try:
            visible = _ObjectSnapshot.from_stat(unresolved_root.lstat())
        except OSError as exc:
            raise TaskBundleError(f"task bundle root path changed: {exc}") from exc
        if not _snapshot_matches(visible, root_snapshot) or stat.S_ISLNK(visible.mode):
            raise TaskBundleError("task bundle root path changed while it was being loaded")

        public_digest = sha256_json(public)
        private_digest = sha256_json(private)
        bundle_digest = sha256_json(
            {
                "schema_version": "bpe.task-bundle.v1",
                "public_sha256": public_digest,
                "private_sha256": private_digest,
            }
        )
        return TaskBundle(
            root=resolved_root,
            public=public,
            private=private,
            public_sha256=public_digest,
            private_sha256=private_digest,
            bundle_sha256=bundle_digest,
            _artifact_bytes=(
                *(("public", path, content) for path, content in public_artifacts),
                *(("grader", path, content) for path, content in private_artifacts),
            ),
        )
    finally:
        if private_fd >= 0:
            os.close(private_fd)
        if public_fd >= 0:
            os.close(public_fd)
        os.close(root_fd)


def build_scoring_contract(bundle: TaskBundle) -> ScoringContract:
    """Derive the exact check manifest the scorer expects from the frozen task bundle."""

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
            input_artifacts={
                "input": ArtifactRef(
                    sha256=case.input_ref.sha256,
                    size_bytes=case.input_ref.size_bytes,
                    media_type="application/octet-stream",
                )
            },
        )
        for case in bundle.private.functional_cases
        for assertion in case.assertions
    )
    semantic_checks = tuple(
        ExpectedCheck(
            stage=Stage.SEMANTICS,
            check_id=f"semantics/{obligation.obligation_id}",
            required=obligation.required,
        )
        for obligation in bundle.private.semantic_obligations
    )
    return ScoringContract(
        task_id=bundle.public.task_id,
        task_version=bundle.public.version,
        task_bundle_sha256=bundle.bundle_sha256,
        checks=(*object_checks, *functional_checks, *semantic_checks),
    )


_PUBLIC_BANNED_KEYS = {
    "grader",
    "hidden",
    "reference",
    "root_cause",
    "mutation",
    "negative_control",
    "semantic_obligation",
}
_TRAINING_EXCLUDED_REPOS = ("cilium", "xdp-tools", "bpftime")
_REQUIRED_CONTROL_KINDS = {"no_op", "delete_operation", "hardcode", "zero_work"}
_MIN_NORMALIZED_TEXT_TOKENS = 24
_MIN_NORMALIZED_TEXT_CHARACTERS = 80

_TEXT_TOKEN = re.compile(
    r"""
    (?:u8|u|U|L)?"(?:\\.|[^"\\])*"
    |(?:u|U|L)?'(?:\\.|[^'\\])*'
    |[A-Za-z_][A-Za-z0-9_]*
    |(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|(?:\d+\.\d*|\.\d+|\d+)(?:[eEpP][+-]?\d+)?)[uUlLfF]*
    |(?:>>=|<<=|\.\.\.|->|\+\+|--|&&|\|\||<=|>=|==|!=|<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\#\#)
    |[^\s]
    """,
    re.VERBOSE,
)


def _walk_keys(value: object) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def _strip_c_comments(text: str) -> str:
    """Remove C comments without changing string or character literal contents."""

    # Translation-phase line splicing happens before comments are recognized. Applying it
    # here also makes differently wrapped preprocessor directives compare consistently.
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(text):
        character = text[index]
        if quote is not None:
            result.append(character)
            if character == "\\" and index + 1 < len(text):
                index += 1
                result.append(text[index])
            elif character == quote:
                quote = None
            index += 1
            continue

        if character in {'"', "'"}:
            quote = character
            result.append(character)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            if newline == -1:
                break
            result.append("\n")
            index = newline + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            result.append(" ")
            index = len(text) if end == -1 else end + 2
            continue
        result.append(character)
        index += 1
    return "".join(result)


def _normalized_text_tokens(text: str) -> tuple[str, ...]:
    normalized = _strip_c_comments(text.removeprefix("\ufeff"))
    return tuple(match.group(0) for match in _TEXT_TOKEN.finditer(normalized))


def _comment_visible_text_tokens(text: str) -> tuple[str, ...]:
    """Tokenize comment bodies too, while ignoring comment delimiters themselves.

    The compiler-oriented view above catches formatting changes and comments inserted
    between copied tokens.  This second, deliberately textual view catches a copied
    private artifact hidden wholesale inside public line or block comments.
    """

    normalized = text.removeprefix("\ufeff")
    normalized = normalized.replace("\\\r\n", "").replace("\\\n", "")
    normalized = normalized.replace("//", " ").replace("/*", " ").replace("*/", " ")
    return tuple(match.group(0) for match in _TEXT_TOKEN.finditer(normalized))


def _substantial_text(tokens: tuple[str, ...]) -> bool:
    return len(tokens) >= _MIN_NORMALIZED_TEXT_TOKENS and sum(map(len, tokens)) >= (
        _MIN_NORMALIZED_TEXT_CHARACTERS
    )


def _contains_token_sequence(
    haystack: tuple[str, ...],
    needle: tuple[str, ...],
) -> bool:
    """Return whether ``needle`` occurs contiguously, using linear-time KMP matching."""

    if not needle or len(needle) > len(haystack):
        return False
    prefix = [0] * len(needle)
    matched = 0
    for index in range(1, len(needle)):
        while matched and needle[index] != needle[matched]:
            matched = prefix[matched - 1]
        if needle[index] == needle[matched]:
            matched += 1
            prefix[index] = matched

    matched = 0
    for token in haystack:
        while matched and token != needle[matched]:
            matched = prefix[matched - 1]
        if token == needle[matched]:
            matched += 1
            if matched == len(needle):
                return True
    return False


def _text_artifact_text(
    bundle: TaskBundle,
    projection: str,
    refs: Iterable[FileRef],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for ref in refs:
        try:
            text = _sealed_artifact_content(bundle, projection, ref.path).decode("utf-8")
        except UnicodeDecodeError:
            continue
        result[ref.path] = text
    return result


def _text_token_views(text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        _normalized_text_tokens(text),
        _comment_visible_text_tokens(text),
    )


def _leakage_comparisons_fit_budget(
    public_text: dict[str, str],
    private_text: dict[str, str],
    public_digests: dict[str, str],
    private_digests: dict[str, str],
    sensitive_tokens: set[str],
) -> bool:
    """Preflight a conservative, deterministic upper bound on leakage-lint work.

    A text pair is inspected through two token views.  Each view performs substantiality,
    equality, and containment scans, so eight source-character units conservatively cover
    the repeated linear passes.  Identifier scans are charged separately.  Preflighting
    before token materialization prevents either artifact-count products or a huge token
    stream from turning the linter into unbounded comparison work.
    """

    remaining = MAX_TASK_LEAKAGE_COMPARISON_WORK

    def consume(units: int) -> bool:
        nonlocal remaining
        if units > remaining:
            return False
        remaining -= units
        return True

    for public_path, public_value in sorted(public_text.items()):
        for private_path, private_value in sorted(private_text.items()):
            if public_digests[public_path] == private_digests[private_path]:
                continue
            pair_work = 1 + 8 * (len(public_value) + len(private_value))
            if not consume(pair_work):
                return False

    for _, public_value in sorted(public_text.items()):
        if not consume(len(public_value)):
            return False
        for token in sorted(sensitive_tokens):
            identifier_work = 1 + len(public_value) + len(token)
            if not consume(identifier_work):
                return False
    return True


def _sealed_artifact_content(bundle: TaskBundle, projection: str, path: str) -> bytes:
    for stored_projection, stored_path, content in bundle._artifact_bytes:
        if (stored_projection, stored_path) == (projection, path):
            return content
    raise TaskBundleError(
        f"task bundle has no sealed bytes for declared artifact {projection}/{path}"
    )


def lint_task(bundle: TaskBundle) -> tuple[LintIssue, ...]:
    issues: list[LintIssue] = []
    public_data = bundle.public.model_dump(mode="json")
    for key in _walk_keys(public_data):
        if any(banned in key for banned in _PUBLIC_BANNED_KEYS):
            issues.append(
                LintIssue(
                    "error",
                    "PUBLIC_PRIVATE_LEAK",
                    f"public field exposes private concept: {key}",
                )
            )

    private = bundle.private
    repo = private.provenance.repository.lower()
    if private.split == "train" and any(name in repo for name in _TRAINING_EXCLUDED_REPOS):
        issues.append(
            LintIssue(
                "error",
                "CONTAMINATED_TRAINING_PROVENANCE",
                "training provenance is from a repository excluded by bpfix-bench policy",
            )
        )

    kinds = {control.kind for control in private.negative_controls}
    for missing in sorted(_REQUIRED_CONTROL_KINDS - kinds):
        issues.append(
            LintIssue(
                "error",
                "MISSING_NEGATIVE_CONTROL",
                f"task lacks required {missing!r} adversarial control",
            )
        )

    identifiers = [control.control_id for control in private.negative_controls]
    if len(identifiers) != len(set(identifiers)):
        issues.append(LintIssue("error", "DUPLICATE_CONTROL_ID", "negative control IDs repeat"))

    case_ids = [case.case_id for case in private.functional_cases]
    if len(case_ids) != len(set(case_ids)):
        issues.append(LintIssue("error", "DUPLICATE_CASE_ID", "functional case IDs repeat"))

    public_refs = tuple(_file_refs(bundle.public))
    private_refs = tuple(_file_refs(private))
    overlap = {ref.sha256 for ref in public_refs} & {ref.sha256 for ref in private_refs}
    if overlap:
        issues.append(
            LintIssue(
                "error",
                "PUBLIC_PRIVATE_ARTIFACT_OVERLAP",
                f"public and private projections share artifact digests: {sorted(overlap)}",
            )
        )

    public_text = _text_artifact_text(bundle, "public", public_refs)
    private_text = _text_artifact_text(bundle, "grader", private_refs)
    public_digests = {ref.path: ref.sha256 for ref in public_refs}
    private_digests = {ref.path: ref.sha256 for ref in private_refs}
    sensitive_tokens = {
        token.lower()
        for token in (
            private.root_cause,
            private.mutation.operator if private.mutation else None,
            *(control.control_id for control in private.negative_controls),
            *(Path(ref.path).name for ref in private_refs),
        )
        if token and len(token) >= 5
    }
    if not _leakage_comparisons_fit_budget(
        public_text,
        private_text,
        public_digests,
        private_digests,
        sensitive_tokens,
    ):
        issues.append(
            LintIssue(
                "error",
                "LEAKAGE_COMPARISON_BUDGET_EXCEEDED",
                "static leakage comparisons exceed the "
                f"{MAX_TASK_LEAKAGE_COMPARISON_WORK}-unit work budget",
            )
        )
        issues.append(
            LintIssue(
                "notice",
                "DYNAMIC_ADMISSION_REQUIRED",
                "static lint completed; authoritative admission still requires reference, "
                "mutant, alternative, and negative controls to run in the pinned microVM",
            )
        )
        return tuple(issues)

    public_tokens = {
        path: _text_token_views(text) for path, text in public_text.items()
    }
    private_tokens = {
        path: _text_token_views(text) for path, text in private_text.items()
    }
    for public_path, public_views in sorted(public_tokens.items()):
        for private_path, private_views in sorted(private_tokens.items()):
            # Exact byte equality already has a clearer digest-overlap diagnostic.
            if public_digests[public_path] == private_digests[private_path]:
                continue
            equivalent = any(
                _substantial_text(private_view) and public_view == private_view
                for public_view, private_view in zip(
                    public_views, private_views, strict=True
                )
            )
            contained = any(
                _substantial_text(private_view)
                and _contains_token_sequence(public_view, private_view)
                for public_view, private_view in zip(
                    public_views, private_views, strict=True
                )
            )
            if equivalent:
                issues.append(
                    LintIssue(
                        "error",
                        "PUBLIC_PRIVATE_NORMALIZED_TEXT_LEAK",
                        f"{public_path} is token-equivalent to private artifact "
                        f"{private_path} after comment and formatting normalization",
                    )
                )
            elif contained:
                issues.append(
                    LintIssue(
                        "error",
                        "PUBLIC_CONTAINS_PRIVATE_TEXT",
                        f"{public_path} contains the complete normalized token sequence "
                        f"of private artifact {private_path}",
                    )
                )

    for ref in public_refs:
        text = public_text.get(ref.path)
        if text is None:
            continue
        text = text.lower()
        leaked = sorted(token for token in sensitive_tokens if token in text)
        if leaked:
            issues.append(
                LintIssue(
                    "error",
                    "PUBLIC_CONTENT_PRIVATE_LEAK",
                    f"{ref.path} contains private identifiers: {leaked}",
                )
            )

    issues.append(
        LintIssue(
            "notice",
            "DYNAMIC_ADMISSION_REQUIRED",
            "static lint completed; authoritative admission still requires reference, mutant, "
            "alternative, and negative controls to run in the pinned microVM",
        )
    )
    return tuple(issues)
