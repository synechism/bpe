"""Fail-closed, static contamination auditing for frozen C source corpora.

This module deliberately performs a static gate only.  Its token fingerprints and n-gram
comparisons cannot prove the absence of contamination through forks, vendored copies,
systematic renaming, semantic rewrites, or AST-level transformations.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, TypeVar
from urllib.parse import unquote, urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from bpe.canonical import CanonicalJSONError, sha256_bytes, sha256_json, strict_json_loads

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
StableId = Annotated[
    str,
    Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]{0,127}$"),
]
CorpusSplit = Literal[
    "train",
    "development",
    "calibration",
    "validation",
    "sealed_eval",
    "benchmark",
]

DETECTOR_VERSION: Literal["bpe.corpus-static-audit.v1"] = (
    "bpe.corpus-static-audit.v1"
)
TOKENIZER_VERSION: Literal["bpe.c-tokenizer.v1"] = "bpe.c-tokenizer.v1"
NGRAM_VERSION: Literal["bpe.c-token-ngram.v1"] = "bpe.c-token-ngram.v1"
_DEFAULT_MANIFEST_MAX_BYTES = 8 * 1024 * 1024
_DEFAULT_SOURCE_MAX_BYTES = 16 * 1024 * 1024
_MAX_FUZZY_COMPARISONS = 1_000_000
_HARD_DENIED_TRAINING_FAMILIES = frozenset({"bpftime", "cilium", "xdp-tools"})
_EVALUATION_SPLITS = frozenset(
    {"development", "calibration", "validation", "sealed_eval", "benchmark"}
)
_REPOSITORY_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class CorpusAuditError(ValueError):
    """A corpus artifact cannot be loaded or audited safely."""


def _normalized_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("paths must be non-empty strings of at most 1024 characters")
    if "\\" in value or "\x00" in value or any(ord(character) < 32 for character in value):
        raise ValueError("paths cannot contain backslashes, NULs, or control characters")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("paths must be normalized and relative")
    if str(path) != value or value.startswith("/") or "//" in value:
        raise ValueError("paths must use normalized relative POSIX syntax")
    return value


NormalizedRelativePath = Annotated[str, AfterValidator(_normalized_relative_path)]


def _non_placeholder_text(value: str, *, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{label} cannot be empty")
    if stripped.casefold() in {"n/a", "none", "tbd", "unknown", "unspecified"}:
        raise ValueError(f"{label} cannot use a placeholder value")
    return stripped


def normalize_repository_identity(repository: str) -> str:
    """Return a conservative ASCII identity for a repository locator.

    URL, SCP-style, and owner/repository spellings normalize deterministically.  Exact
    path components are used rather than substring matching, and ambiguous Unicode
    spellings are rejected instead of being treated as trusted provenance.
    """

    raw = unicodedata.normalize("NFKC", _non_placeholder_text(repository, label="repository"))
    if any(ord(character) < 32 for character in raw) or "\\" in raw:
        raise ValueError("repository identities cannot contain controls or backslashes")

    host = ""
    repository_path = raw

    def normalize_host(value: str) -> str:
        normalized = value.casefold()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        if not normalized or normalized.endswith("."):
            raise ValueError("repository hostname has an invalid terminal dot")
        return normalized.removeprefix("www.")

    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() not in {"git", "http", "https", "ssh"}:
            raise ValueError("repository URL uses an unsupported scheme")
        if not parsed.hostname:
            raise ValueError("repository URL requires a hostname")
        host = normalize_host(parsed.hostname)
        repository_path = unquote(parsed.path)
    else:
        scp = re.fullmatch(r"(?:[^@/:]+@)?([^/:]+):(.+)", raw)
        if scp is not None:
            host = normalize_host(scp.group(1))
            repository_path = unquote(scp.group(2))
        else:
            repository_path = unquote(raw.split("#", 1)[0].split("?", 1)[0])

    repository_path = repository_path.strip("/")
    parts = [part.casefold() for part in repository_path.split("/") if part]
    if not parts:
        raise ValueError("repository identity has no path components")
    if not host and len(parts) == 2:
        host = "github.com"
    if host in {
        "codeload.github.com",
        "raw.github.com",
        "raw.githubusercontent.com",
    }:
        if len(parts) < 2:
            raise ValueError("GitHub content URL lacks an owner/repository identity")
        host = "github.com"
        parts = parts[:2]
    elif host == "api.github.com":
        if len(parts) < 3 or parts[0] != "repos":
            raise ValueError("GitHub API URL is not a repository identity")
        host = "github.com"
        parts = parts[1:3]
    elif host.endswith(".github.com") or host.endswith(".githubusercontent.com"):
        raise ValueError("unsupported GitHub service URL for repository provenance")
    while parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if not parts[-1]:
        raise ValueError("repository identity has an empty repository name")
    if host == "github.com" and len(parts) != 2:
        raise ValueError("GitHub repository identities must be exactly owner/repository")
    if not all(_REPOSITORY_SEGMENT.fullmatch(part) for part in parts):
        raise ValueError("repository identity contains a non-ASCII or invalid component")
    if host and not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("repository hostname is invalid")
    return "/".join((host, *parts)) if host else "/".join(parts)


def normalize_repository_family(repository: str) -> str:
    """Return the exact normalized repository basename used as a lineage family."""

    return normalize_repository_identity(repository).rsplit("/", 1)[-1]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        revalidate_instances="always",
    )


class CorpusProvenance(_FrozenModel):
    """Required upstream identity for one corpus source artifact."""

    repository: Annotated[str, Field(min_length=1, max_length=1024)]
    commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    source_path: NormalizedRelativePath
    license: Annotated[str, Field(min_length=1, max_length=256)]

    @field_validator("repository")
    @classmethod
    def repository_must_be_unambiguous(cls, value: str) -> str:
        value = _non_placeholder_text(value, label="repository")
        normalize_repository_identity(value)
        return value

    @field_validator("license")
    @classmethod
    def license_must_be_real(cls, value: str) -> str:
        return _non_placeholder_text(value, label="license")

    @field_validator("commit")
    @classmethod
    def commit_cannot_be_a_sentinel(cls, value: str) -> str:
        if value == "0" * 40:
            raise ValueError("provenance commit cannot be an all-zero sentinel")
        return value

    @property
    def repository_identity(self) -> str:
        return normalize_repository_identity(self.repository)

    @property
    def repository_family(self) -> str:
        return normalize_repository_family(self.repository)


class CorpusSource(_FrozenModel):
    """One fully enumerated C source artifact and its split/lineage identity."""

    source_id: StableId
    path: NormalizedRelativePath
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0, le=_DEFAULT_SOURCE_MAX_BYTES)]
    language: Literal["c"] = "c"
    split: CorpusSplit
    contamination_group: StableId
    lineage_group: StableId
    clone_group: StableId
    provenance: CorpusProvenance


class CorpusManifest(_FrozenModel):
    """Frozen, closed-tree manifest for a candidate corpus or separate benchmark."""

    schema_version: Literal["bpe.corpus-manifest.v1"] = "bpe.corpus-manifest.v1"
    manifest_kind: Literal["corpus", "benchmark"]
    corpus_id: StableId
    tree_mode: Literal["closed"] = "closed"
    sources: Annotated[
        tuple[CorpusSource, ...],
        Field(min_length=1, max_length=100_000),
    ]

    @model_validator(mode="after")
    def identities_and_splits_are_valid(self) -> CorpusManifest:
        source_ids = [source.source_id for source in self.sources]
        paths = [source.path for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("corpus source IDs must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("corpus source paths must be unique")
        if self.manifest_kind == "benchmark":
            if any(source.split != "benchmark" for source in self.sources):
                raise ValueError("benchmark manifests may contain only benchmark-split sources")
        elif any(source.split == "benchmark" for source in self.sources):
            raise ValueError("candidate corpus manifests cannot contain benchmark-split sources")
        return self


class CorpusAuditPolicy(_FrozenModel):
    """Frozen policy for the conservative, blocking static contamination detector."""

    schema_version: Literal["bpe.corpus-audit-policy.v1"] = (
        "bpe.corpus-audit-policy.v1"
    )
    policy_id: StableId
    detector_version: Literal["bpe.corpus-static-audit.v1"] = DETECTOR_VERSION
    tokenizer_version: Literal["bpe.c-tokenizer.v1"] = TOKENIZER_VERSION
    ngram_version: Literal["bpe.c-token-ngram.v1"] = NGRAM_VERSION
    ngram_size: Annotated[int, Field(ge=3, le=7)] = 5
    minimum_tokens: Annotated[int, Field(ge=16, le=4096)] = 40
    jaccard_threshold: Annotated[
        float,
        Field(gt=0, le=0.95, allow_inf_nan=False),
    ] = 0.85
    containment_threshold: Annotated[
        float,
        Field(gt=0, le=0.99, allow_inf_nan=False),
    ] = 0.95
    training_splits: tuple[CorpusSplit, ...] = ("train",)
    evaluation_splits: tuple[CorpusSplit, ...] = (
        "development",
        "calibration",
        "validation",
        "sealed_eval",
        "benchmark",
    )
    denied_training_repository_families: tuple[str, ...] = (
        "bpftime",
        "cilium",
        "xdp-tools",
    )

    @model_validator(mode="after")
    def policy_cannot_weaken_hard_boundaries(self) -> CorpusAuditPolicy:
        if set(self.training_splits) != {"train"}:
            raise ValueError("the static audit training split is fixed to 'train'")
        if set(self.evaluation_splits) != _EVALUATION_SPLITS:
            raise ValueError("the static audit evaluation-like split set is fixed")
        if len(self.denied_training_repository_families) != len(
            set(self.denied_training_repository_families)
        ):
            raise ValueError("denied repository families must be unique")
        normalized = {
            normalize_repository_family(family)
            for family in self.denied_training_repository_families
        }
        if not normalized >= _HARD_DENIED_TRAINING_FAMILIES:
            raise ValueError("the hard training repository denylist cannot be weakened")
        if self.minimum_tokens < self.ngram_size:
            raise ValueError("minimum token gate cannot be smaller than the n-gram size")
        return self


class CorpusAuditIssue(_FrozenModel):
    """A blocking static hit, skipped scan, or detector error."""

    severity: Literal["error"] = "error"
    kind: Literal["hit", "skip", "error"]
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    message: Annotated[str, Field(min_length=1, max_length=4096)]
    source_refs: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = ()
    jaccard: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    containment: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None


class CorpusFingerprint(_FrozenModel):
    """Deterministic comment/format-insensitive identity for one scanned C artifact."""

    corpus_id: StableId
    source_id: StableId
    token_count: Annotated[int, Field(ge=0)]
    unique_ngram_count: Annotated[int, Field(ge=0)]
    token_sha256: Sha256
    ngram_sha256: Sha256


class CorpusSimilarity(_FrozenModel):
    """Reported token n-gram similarity for one train/evaluation-like pair."""

    training_corpus_id: StableId
    training_source_id: StableId
    evaluation_corpus_id: StableId
    evaluation_source_id: StableId
    training_ngram_count: Annotated[int, Field(ge=1)]
    evaluation_ngram_count: Annotated[int, Field(ge=1)]
    shared_ngram_count: Annotated[int, Field(ge=0)]
    jaccard: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    containment: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    blocking: bool


class CorpusAuditReport(_FrozenModel):
    """Static-only audit result; it is not a claim that a corpus is training-ready.

    Token n-grams cannot prove absence of fork, vendored, renamed, semantic, or AST-level
    contamination.  A passing report therefore means only that this frozen static detector
    completed without a hit, skip, or error for the exact bound inputs.
    """

    schema_version: Literal["bpe.corpus-audit-report.v1"] = (
        "bpe.corpus-audit-report.v1"
    )
    detector_version: Literal["bpe.corpus-static-audit.v1"] = DETECTOR_VERSION
    corpus_id: StableId
    corpus_manifest_sha256: Sha256
    benchmark_corpus_id: StableId
    benchmark_manifest_sha256: Sha256
    policy_id: StableId
    policy_sha256: Sha256
    audit_inputs_sha256: Sha256
    total_source_count: Annotated[int, Field(ge=0)]
    scanned_source_count: Annotated[int, Field(ge=0)]
    fuzzy_eligible_source_count: Annotated[int, Field(ge=0)]
    expected_comparison_count: Annotated[int, Field(ge=0)]
    evaluated_comparison_count: Annotated[int, Field(ge=0)]
    fingerprints: tuple[CorpusFingerprint, ...]
    comparisons: tuple[CorpusSimilarity, ...]
    issues: tuple[CorpusAuditIssue, ...]
    static_audit_passed: bool

    @model_validator(mode="after")
    def pass_flag_is_fail_closed(self) -> CorpusAuditReport:
        if self.scanned_source_count != len(self.fingerprints):
            raise ValueError("scanned source count does not match fingerprints")
        if self.evaluated_comparison_count != len(self.comparisons):
            raise ValueError("comparison count does not match reported comparisons")
        if self.scanned_source_count > self.total_source_count:
            raise ValueError("scanned source count exceeds the frozen source count")
        if self.fuzzy_eligible_source_count > self.scanned_source_count:
            raise ValueError("fuzzy-eligible source count exceeds scanned sources")
        if self.evaluated_comparison_count > self.expected_comparison_count:
            raise ValueError("evaluated comparison count exceeds the frozen matrix")
        fingerprint_ids = {
            (fingerprint.corpus_id, fingerprint.source_id)
            for fingerprint in self.fingerprints
        }
        if len(fingerprint_ids) != len(self.fingerprints):
            raise ValueError("fingerprint source identities must be unique")
        complete = (
            not self.issues
            and self.total_source_count >= 2
            and self.expected_comparison_count >= 1
            and self.scanned_source_count == self.total_source_count
            and self.fuzzy_eligible_source_count == self.total_source_count
            and self.evaluated_comparison_count == self.expected_comparison_count
            and not any(comparison.blocking for comparison in self.comparisons)
        )
        if self.static_audit_passed != complete:
            raise ValueError("static audit pass flag does not match fail-closed report state")
        return self


@dataclass(frozen=True)
class LoadedCorpusSource:
    source: CorpusSource
    content: bytes


@dataclass(frozen=True)
class LoadedCorpus:
    root: Path
    manifest: CorpusManifest
    sources: tuple[LoadedCorpusSource, ...]


ModelT = TypeVar("ModelT", bound=BaseModel)


def _open_relative_component(
    name: str,
    *,
    directory_fd: int,
    directory: bool,
    label: str,
) -> int:
    """Open one path component without following it or racing an ancestor swap."""

    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise CorpusAuditError(f"cannot inspect {label}: {exc}") from exc
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if stat.S_ISLNK(before.st_mode) or not expected_kind(before.st_mode):
        expected = "directory" if directory else "regular file"
        raise CorpusAuditError(f"{label} is not a non-symlink {expected}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise CorpusAuditError(f"cannot open {label}: {exc}") from exc
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or not expected_kind(opened.st_mode)
    ):
        os.close(descriptor)
        raise CorpusAuditError(f"{label} changed while it was being opened")
    return descriptor


def _safe_read_relative(
    root: Path,
    relative_path: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read beneath ``root`` through pinned directory descriptors, never path re-resolution."""

    parts = PurePosixPath(_normalized_relative_path(relative_path)).parts
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise CorpusAuditError(f"cannot inspect corpus root: {exc}") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise CorpusAuditError("corpus root is not a regular, non-symlink directory")
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(root, root_flags)
    except OSError as exc:
        raise CorpusAuditError(f"cannot open corpus root: {exc}") from exc
    opened_root = os.fstat(directory_fd)
    if (opened_root.st_dev, opened_root.st_ino) != (
        root_metadata.st_dev,
        root_metadata.st_ino,
    ):
        os.close(directory_fd)
        raise CorpusAuditError("corpus root changed while it was being opened")

    try:
        for index, part in enumerate(parts[:-1]):
            next_fd = _open_relative_component(
                part,
                directory_fd=directory_fd,
                directory=True,
                label=f"{label} directory component {index}",
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = _open_relative_component(
            parts[-1],
            directory_fd=directory_fd,
            directory=False,
            label=label,
        )
        try:
            opened = os.fstat(file_fd)
            if opened.st_size > max_bytes:
                raise CorpusAuditError(
                    f"{label} exceeds the {max_bytes}-byte safety limit"
                )
            with os.fdopen(file_fd, "rb") as handle:
                file_fd = -1
                content = handle.read(max_bytes + 1)
                after = os.fstat(handle.fileno())
            if len(content) > max_bytes:
                raise CorpusAuditError(
                    f"{label} exceeds the {max_bytes}-byte safety limit"
                )
            if len(content) != opened.st_size or (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) != (
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ):
                raise CorpusAuditError(f"{label} changed while it was being read")
            return content
        finally:
            if file_fd >= 0:
                os.close(file_fd)
    finally:
        os.close(directory_fd)


def _safe_read_regular(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CorpusAuditError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CorpusAuditError(f"{label} is not a regular, non-symlink file: {path}")
    if metadata.st_size > max_bytes:
        raise CorpusAuditError(f"{label} exceeds the {max_bytes}-byte safety limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise CorpusAuditError(f"{label} changed to a non-regular file: {path}")
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise CorpusAuditError(f"{label} changed while it was being opened: {path}")
            content = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise CorpusAuditError(f"cannot read {label} {path}: {exc}") from exc
    if len(content) > max_bytes:
        raise CorpusAuditError(f"{label} exceeds the {max_bytes}-byte safety limit: {path}")
    if len(content) != opened.st_size or (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ):
        raise CorpusAuditError(f"{label} changed while it was being read: {path}")
    return content


def _strict_model_from_bytes(raw: bytes, model_type: type[ModelT], *, label: str) -> ModelT:
    try:
        value = strict_json_loads(raw)
        return model_type.model_validate(value)
    except (CanonicalJSONError, ValidationError, ValueError) as exc:
        raise CorpusAuditError(f"invalid {label}: {exc}") from exc


def _verify_closed_tree(root: Path, metadata_name: str, manifest: CorpusManifest) -> None:
    expected_files = {metadata_name, *(source.path for source in manifest.sources)}
    expected_directories = {
        parent.as_posix()
        for path in expected_files
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    }
    actual_files: set[str] = set()
    actual_directories: set[str] = set()

    def walk_error(error: OSError) -> None:
        raise CorpusAuditError(f"cannot traverse corpus tree: {error}")

    for directory, directory_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=walk_error,
    ):
        directory_path = Path(directory)
        for name in directory_names:
            child = directory_path / name
            if child.is_symlink():
                raise CorpusAuditError(f"corpus tree contains a symlinked directory: {child}")
            actual_directories.add(child.relative_to(root).as_posix())
        for name in file_names:
            child = directory_path / name
            if child.is_symlink():
                raise CorpusAuditError(f"corpus tree contains a symlinked file: {child}")
            actual_files.add(child.relative_to(root).as_posix())

    extra_files = actual_files - expected_files
    missing_files = expected_files - actual_files
    extra_directories = actual_directories - expected_directories
    missing_directories = expected_directories - actual_directories
    if extra_files or missing_files or extra_directories or missing_directories:
        raise CorpusAuditError(
            "corpus tree is not closed; "
            f"unlisted_files={sorted(extra_files)}, missing_files={sorted(missing_files)}, "
            f"unlisted_directories={sorted(extra_directories)}, "
            f"missing_directories={sorted(missing_directories)}"
        )


def load_corpus(
    manifest_path: Path,
    *,
    manifest_max_bytes: int = _DEFAULT_MANIFEST_MAX_BYTES,
    source_max_bytes: int = _DEFAULT_SOURCE_MAX_BYTES,
) -> LoadedCorpus:
    """Load and freeze a manifest whose parent is an exactly closed source tree."""

    unresolved = manifest_path.absolute()
    root_unresolved = unresolved.parent
    if root_unresolved.is_symlink() or unresolved.is_symlink():
        raise CorpusAuditError("corpus root and manifest must not be symlinks")
    try:
        root = root_unresolved.resolve(strict=True)
    except OSError as exc:
        raise CorpusAuditError(f"cannot resolve corpus root: {exc}") from exc
    if not root.is_dir():
        raise CorpusAuditError(f"corpus root is not a directory: {root}")
    metadata_name = _normalized_relative_path(unresolved.name)
    raw_manifest = _safe_read_relative(
        root,
        metadata_name,
        max_bytes=manifest_max_bytes,
        label="corpus manifest",
    )
    manifest = _strict_model_from_bytes(
        raw_manifest,
        CorpusManifest,
        label="corpus manifest JSON",
    )
    _verify_closed_tree(root, metadata_name, manifest)

    loaded: list[LoadedCorpusSource] = []
    for source in manifest.sources:
        content = _safe_read_relative(
            root,
            source.path,
            max_bytes=min(source_max_bytes, _DEFAULT_SOURCE_MAX_BYTES),
            label=f"corpus source {source.source_id}",
        )
        actual = (sha256_bytes(content), len(content))
        expected = (source.sha256, source.size_bytes)
        if actual != expected:
            raise CorpusAuditError(
                f"source integrity mismatch for {source.source_id}: "
                f"expected {expected[0]}/{expected[1]}, got {actual[0]}/{actual[1]}"
            )
        loaded.append(LoadedCorpusSource(source=source, content=content))
    _verify_closed_tree(root, metadata_name, manifest)
    return LoadedCorpus(root=root, manifest=manifest, sources=tuple(loaded))


def load_corpus_audit_policy(path: Path) -> CorpusAuditPolicy:
    """Load a strict policy JSON file, rejecting symlinks, duplicates, and nonfinite data."""

    unresolved = path.absolute()
    if unresolved.is_symlink():
        raise CorpusAuditError("corpus audit policy must not be a symlink")
    raw = _safe_read_regular(
        unresolved,
        max_bytes=_DEFAULT_MANIFEST_MAX_BYTES,
        label="corpus audit policy",
    )
    return _strict_model_from_bytes(raw, CorpusAuditPolicy, label="corpus audit policy JSON")


def _strip_c_comments(source: str) -> str:
    source = source.replace("\\\r\n", "").replace("\\\n", "")
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is not None:
            result.append(character)
            if character == "\\" and index + 1 < len(source):
                index += 1
                result.append(source[index])
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            result.append(character)
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            if newline == -1:
                return "".join(result) + " "
            result.append("\n")
            index = newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end == -1:
                raise CorpusAuditError("unterminated C block comment")
            result.append(" ")
            index = end + 2
            continue
        result.append(character)
        index += 1
    if quote is not None:
        raise CorpusAuditError("unterminated C string or character literal")
    return "".join(result)


_C_TOKEN = re.compile(
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


def tokenize_c(content: bytes) -> tuple[str, ...]:
    """Return deterministic C tokens after UTF-8 decoding and comment normalization."""

    try:
        source = content.decode("utf-8", errors="strict").removeprefix("\ufeff")
    except UnicodeDecodeError as exc:
        raise CorpusAuditError("C source is not valid UTF-8") from exc
    normalized = _strip_c_comments(source)
    return tuple(match.group(0) for match in _C_TOKEN.finditer(normalized))


def _sequence_digest(tokens: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for token in tokens:
        encoded = token.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _token_ngrams(tokens: tuple[str, ...], size: int) -> frozenset[tuple[str, ...]]:
    if len(tokens) < size:
        return frozenset()
    return frozenset(tuple(tokens[index : index + size]) for index in range(len(tokens) - size + 1))


def _ngram_digest(ngrams: frozenset[tuple[str, ...]]) -> str:
    digest = hashlib.sha256()
    for ngram in sorted(ngrams):
        for token in ngram:
            encoded = token.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(b"\xff")
    return digest.hexdigest()


@dataclass(frozen=True)
class _Scan:
    loaded: LoadedCorpusSource
    corpus_id: str
    tokens: tuple[str, ...]
    ngrams: frozenset[tuple[str, ...]]
    fingerprint: CorpusFingerprint


def _source_ref(corpus_id: str, source_id: str) -> str:
    return f"{corpus_id}:{source_id}"


def _validate_loaded(loaded: LoadedCorpus) -> LoadedCorpus:
    manifest = CorpusManifest.model_validate(loaded.manifest.model_dump(mode="python"))
    by_id = {item.source.source_id: item for item in loaded.sources}
    if len(by_id) != len(loaded.sources) or set(by_id) != {
        source.source_id for source in manifest.sources
    }:
        raise CorpusAuditError("loaded corpus sources do not exactly match the manifest")
    ordered: list[LoadedCorpusSource] = []
    for source in manifest.sources:
        item = by_id[source.source_id]
        if item.source != source:
            raise CorpusAuditError(f"loaded source metadata changed: {source.source_id}")
        if (sha256_bytes(item.content), len(item.content)) != (source.sha256, source.size_bytes):
            raise CorpusAuditError(f"loaded source content changed: {source.source_id}")
        ordered.append(item)
    return LoadedCorpus(root=loaded.root, manifest=manifest, sources=tuple(ordered))


def _group_cross_split_issues(
    training: list[tuple[str, CorpusSource]],
    evaluation: list[tuple[str, CorpusSource]],
    *,
    attribute: Literal["contamination_group", "lineage_group", "clone_group"],
    code: str,
) -> list[CorpusAuditIssue]:
    train_groups: dict[str, list[str]] = defaultdict(list)
    evaluation_groups: dict[str, list[str]] = defaultdict(list)
    for corpus_id, source in training:
        train_groups[getattr(source, attribute)].append(_source_ref(corpus_id, source.source_id))
    for corpus_id, source in evaluation:
        evaluation_groups[getattr(source, attribute)].append(
            _source_ref(corpus_id, source.source_id)
        )
    issues: list[CorpusAuditIssue] = []
    for group in sorted(set(train_groups) & set(evaluation_groups)):
        refs = tuple(sorted((*train_groups[group], *evaluation_groups[group])))
        issues.append(
            CorpusAuditIssue(
                kind="hit",
                code=code,
                message=f"{attribute} {group!r} crosses train and evaluation-like splits",
                source_refs=refs,
            )
        )
    return issues


def audit_corpus(
    corpus: LoadedCorpus,
    benchmark: LoadedCorpus,
    policy: CorpusAuditPolicy,
) -> CorpusAuditReport:
    """Run the frozen blocking static gate against a separate frozen benchmark."""

    corpus = _validate_loaded(corpus)
    benchmark = _validate_loaded(benchmark)
    policy = CorpusAuditPolicy.model_validate(policy.model_dump(mode="python"))
    if corpus.manifest.manifest_kind != "corpus":
        raise CorpusAuditError("the candidate input must use manifest_kind='corpus'")
    if benchmark.manifest.manifest_kind != "benchmark":
        raise CorpusAuditError("the comparison input must use manifest_kind='benchmark'")
    if corpus.manifest.corpus_id == benchmark.manifest.corpus_id:
        raise CorpusAuditError("candidate and benchmark corpus IDs must differ")

    corpus_digest = sha256_json(corpus.manifest)
    benchmark_digest = sha256_json(benchmark.manifest)
    policy_digest = sha256_json(policy)
    audit_inputs_digest = sha256_json(
        {
            "schema_version": "bpe.corpus-audit-inputs.v1",
            "detector_version": DETECTOR_VERSION,
            "corpus_manifest_sha256": corpus_digest,
            "benchmark_manifest_sha256": benchmark_digest,
            "policy_sha256": policy_digest,
        }
    )
    issues: list[CorpusAuditIssue] = []
    combined_loaded = (
        *((corpus.manifest.corpus_id, item) for item in corpus.sources),
        *((benchmark.manifest.corpus_id, item) for item in benchmark.sources),
    )
    combined_sources = [
        (corpus_id, item.source) for corpus_id, item in combined_loaded
    ]
    source_id_groups: dict[str, list[str]] = defaultdict(list)
    digest_groups: dict[str, list[str]] = defaultdict(list)
    for corpus_id, source in combined_sources:
        reference = _source_ref(corpus_id, source.source_id)
        source_id_groups[source.source_id].append(reference)
        digest_groups[source.sha256].append(reference)
    for source_id, refs in sorted(source_id_groups.items()):
        if len(refs) > 1:
            issues.append(
                CorpusAuditIssue(
                    kind="hit",
                    code="DUPLICATE_SOURCE_ID",
                    message=f"source ID {source_id!r} is duplicated across frozen manifests",
                    source_refs=tuple(sorted(refs)),
                )
            )
    for digest, refs in sorted(digest_groups.items()):
        if len(refs) > 1:
            issues.append(
                CorpusAuditIssue(
                    kind="hit",
                    code="EXACT_DIGEST_DUPLICATE",
                    message=f"exact source digest {digest} occurs more than once",
                    source_refs=tuple(sorted(refs)),
                )
            )

    training = [
        (corpus_id, source)
        for corpus_id, source in combined_sources
        if source.split in policy.training_splits
    ]
    evaluation = [
        (corpus_id, source)
        for corpus_id, source in combined_sources
        if source.split in policy.evaluation_splits
    ]
    if not training:
        issues.append(
            CorpusAuditIssue(
                kind="error",
                code="NO_TRAINING_SOURCES",
                message="candidate corpus contains no training-split sources",
            )
        )
    expected_comparison_count = len(training) * len(evaluation)
    comparison_budget_exceeded = expected_comparison_count > _MAX_FUZZY_COMPARISONS
    if comparison_budget_exceeded:
        issues.append(
            CorpusAuditIssue(
                kind="error",
                code="FUZZY_COMPARISON_BUDGET_EXCEEDED",
                message=(
                    f"the frozen comparison matrix requires {expected_comparison_count} "
                    f"pairs; the detector safety limit is {_MAX_FUZZY_COMPARISONS}"
                ),
            )
        )
    issues.extend(
        _group_cross_split_issues(
            training,
            evaluation,
            attribute="contamination_group",
            code="CROSS_SPLIT_CONTAMINATION_GROUP",
        )
    )
    issues.extend(
        _group_cross_split_issues(
            training,
            evaluation,
            attribute="lineage_group",
            code="CROSS_SPLIT_LINEAGE_GROUP",
        )
    )
    issues.extend(
        _group_cross_split_issues(
            training,
            evaluation,
            attribute="clone_group",
            code="CROSS_SPLIT_CLONE_GROUP",
        )
    )

    training_families: dict[str, list[str]] = defaultdict(list)
    evaluation_families: dict[str, list[str]] = defaultdict(list)
    denied_families = {
        normalize_repository_family(family)
        for family in policy.denied_training_repository_families
    }
    for corpus_id, source in training:
        family = source.provenance.repository_family
        reference = _source_ref(corpus_id, source.source_id)
        training_families[family].append(reference)
        if family in denied_families:
            issues.append(
                CorpusAuditIssue(
                    kind="hit",
                    code="TRAINING_REPOSITORY_DENIED",
                    message=f"training source belongs to hard-denied repository family {family!r}",
                    source_refs=(reference,),
                )
            )
    for corpus_id, source in evaluation:
        evaluation_families[source.provenance.repository_family].append(
            _source_ref(corpus_id, source.source_id)
        )
    for family in sorted(set(training_families) & set(evaluation_families)):
        issues.append(
            CorpusAuditIssue(
                kind="hit",
                code="CROSS_SPLIT_REPOSITORY_FAMILY",
                message=f"repository family {family!r} crosses train and evaluation-like splits",
                source_refs=tuple(
                    sorted((*training_families[family], *evaluation_families[family]))
                ),
            )
        )

    scans: dict[tuple[str, str], _Scan] = {}
    token_digest_groups: dict[str, list[tuple[str, CorpusSource]]] = defaultdict(list)
    for corpus_id, item in sorted(
        combined_loaded,
        key=lambda value: (value[0], value[1].source.source_id),
    ):
        source = item.source
        reference = _source_ref(corpus_id, source.source_id)
        try:
            tokens = tokenize_c(item.content)
            ngrams = _token_ngrams(tokens, policy.ngram_size)
        except CorpusAuditError as exc:
            issues.append(
                CorpusAuditIssue(
                    kind="error",
                    code="SOURCE_TOKENIZATION_ERROR",
                    message=f"cannot tokenize {reference}: {exc}",
                    source_refs=(reference,),
                )
            )
            continue
        token_digest = _sequence_digest(tokens)
        fingerprint = CorpusFingerprint(
            corpus_id=corpus_id,
            source_id=source.source_id,
            token_count=len(tokens),
            unique_ngram_count=len(ngrams),
            token_sha256=token_digest,
            ngram_sha256=_ngram_digest(ngrams),
        )
        scans[(corpus_id, source.source_id)] = _Scan(
            loaded=item,
            corpus_id=corpus_id,
            tokens=tokens,
            ngrams=ngrams,
            fingerprint=fingerprint,
        )
        token_digest_groups[token_digest].append((corpus_id, source))
        if len(tokens) < policy.minimum_tokens:
            issues.append(
                CorpusAuditIssue(
                    kind="skip",
                    code="INSUFFICIENT_TOKENS_FOR_FUZZY_SCAN",
                    message=(
                        f"{reference} has {len(tokens)} tokens; the frozen minimum is "
                        f"{policy.minimum_tokens}"
                    ),
                    source_refs=(reference,),
                )
            )

    for token_digest, members in sorted(token_digest_groups.items()):
        content_digests = {source.sha256 for _, source in members}
        if len(members) > 1 and len(content_digests) > 1:
            issues.append(
                CorpusAuditIssue(
                    kind="hit",
                    code="NORMALIZED_TOKEN_DUPLICATE",
                    message=(
                        "comment/format-insensitive token fingerprint "
                        f"{token_digest} occurs more than once"
                    ),
                    source_refs=tuple(
                        sorted(
                            _source_ref(corpus_id, source.source_id)
                            for corpus_id, source in members
                        )
                    ),
                )
            )

    training_scans = (
        []
        if comparison_budget_exceeded
        else [
            scans[(corpus_id, source.source_id)]
            for corpus_id, source in training
            if (corpus_id, source.source_id) in scans
            and len(scans[(corpus_id, source.source_id)].tokens) >= policy.minimum_tokens
        ]
    )
    evaluation_scans = (
        []
        if comparison_budget_exceeded
        else [
            scans[(corpus_id, source.source_id)]
            for corpus_id, source in evaluation
            if (corpus_id, source.source_id) in scans
            and len(scans[(corpus_id, source.source_id)].tokens) >= policy.minimum_tokens
        ]
    )
    comparisons: list[CorpusSimilarity] = []
    for training_scan in sorted(
        training_scans,
        key=lambda scan: (scan.corpus_id, scan.loaded.source.source_id),
    ):
        for evaluation_scan in sorted(
            evaluation_scans,
            key=lambda scan: (scan.corpus_id, scan.loaded.source.source_id),
        ):
            intersection = training_scan.ngrams & evaluation_scan.ngrams
            union = training_scan.ngrams | evaluation_scan.ngrams
            jaccard = len(intersection) / len(union)
            containment = len(intersection) / min(
                len(training_scan.ngrams),
                len(evaluation_scan.ngrams),
            )
            same_digest = (
                training_scan.loaded.source.sha256
                == evaluation_scan.loaded.source.sha256
            )
            same_tokens = (
                training_scan.fingerprint.token_sha256
                == evaluation_scan.fingerprint.token_sha256
            )
            fuzzy_hit = (
                jaccard >= policy.jaccard_threshold
                or containment >= policy.containment_threshold
            )
            blocking = same_digest or same_tokens or fuzzy_hit
            comparison = CorpusSimilarity(
                training_corpus_id=training_scan.corpus_id,
                training_source_id=training_scan.loaded.source.source_id,
                evaluation_corpus_id=evaluation_scan.corpus_id,
                evaluation_source_id=evaluation_scan.loaded.source.source_id,
                training_ngram_count=len(training_scan.ngrams),
                evaluation_ngram_count=len(evaluation_scan.ngrams),
                shared_ngram_count=len(intersection),
                jaccard=jaccard,
                containment=containment,
                blocking=blocking,
            )
            comparisons.append(comparison)
            if fuzzy_hit and not same_digest and not same_tokens:
                pair_refs = (
                    _source_ref(training_scan.corpus_id, training_scan.loaded.source.source_id),
                    _source_ref(
                        evaluation_scan.corpus_id,
                        evaluation_scan.loaded.source.source_id,
                    ),
                )
                issues.append(
                    CorpusAuditIssue(
                        kind="hit",
                        code="FUZZY_EVALUATION_CONTAMINATION",
                        message=(
                            "token n-gram similarity meets a frozen blocking threshold: "
                            f"Jaccard={jaccard:.6f}, containment={containment:.6f}"
                        ),
                        source_refs=pair_refs,
                        jaccard=jaccard,
                        containment=containment,
                    )
                )

    total_source_count = len(combined_sources)
    eligible_count = sum(
        len(scan.tokens) >= policy.minimum_tokens for scan in scans.values()
    )
    fingerprints = tuple(
        scan.fingerprint
        for scan in sorted(
            scans.values(),
            key=lambda item: (item.corpus_id, item.loaded.source.source_id),
        )
    )
    sorted_issues = tuple(
        sorted(
            issues,
            key=lambda issue: (issue.code, issue.source_refs, issue.message),
        )
    )
    complete = (
        not sorted_issues
        and len(fingerprints) == total_source_count
        and eligible_count == total_source_count
        and len(comparisons) == expected_comparison_count
        and not any(comparison.blocking for comparison in comparisons)
    )
    return CorpusAuditReport(
        corpus_id=corpus.manifest.corpus_id,
        corpus_manifest_sha256=corpus_digest,
        benchmark_corpus_id=benchmark.manifest.corpus_id,
        benchmark_manifest_sha256=benchmark_digest,
        policy_id=policy.policy_id,
        policy_sha256=policy_digest,
        audit_inputs_sha256=audit_inputs_digest,
        total_source_count=total_source_count,
        scanned_source_count=len(fingerprints),
        fuzzy_eligible_source_count=eligible_count,
        expected_comparison_count=expected_comparison_count,
        evaluated_comparison_count=len(comparisons),
        fingerprints=fingerprints,
        comparisons=tuple(comparisons),
        issues=sorted_issues,
        static_audit_passed=complete,
    )


def corpus_audit_report_sha256(report: CorpusAuditReport) -> str:
    """Return the canonical digest used to freeze or publish an audit report."""

    validated = CorpusAuditReport.model_validate(report.model_dump(mode="python"))
    return sha256_json(validated)


__all__ = [
    "CorpusAuditError",
    "CorpusAuditIssue",
    "CorpusAuditPolicy",
    "CorpusAuditReport",
    "CorpusFingerprint",
    "CorpusManifest",
    "CorpusProvenance",
    "CorpusSimilarity",
    "CorpusSource",
    "LoadedCorpus",
    "LoadedCorpusSource",
    "audit_corpus",
    "corpus_audit_report_sha256",
    "load_corpus",
    "load_corpus_audit_policy",
    "normalize_repository_family",
    "normalize_repository_identity",
    "tokenize_c",
]
