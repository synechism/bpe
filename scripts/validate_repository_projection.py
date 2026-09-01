from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath

PUBLIC_GITHUB_REPOSITORY = "synechism/bpe"
PUBLIC_OPERATIONAL_OVERLAY = {
    ".github/workflows/ci.yml": "100644",
    ".github/workflows/native-qualification.yml": "100644",
}
PUBLIC_TEST_OVERLAY = {
    "tests/integration/cgroup_v2_native_probe.py": "100644",
    "tests/integration/inert_fixture_launcher_native_probe.py": "100644",
}
PUBLIC_SMOKE_TASK = {
    "tasks/smoke/missing-null/public/broken.c": "100644",
    "tasks/smoke/missing-null/public/prompt.md": "100644",
    "tasks/smoke/missing-null/public/task.json": "100644",
}
PUBLIC_SOURCE_ROOT_FILES = {
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
}
PUBLIC_SOURCE_TREES = {
    "docs",
    "policies",
    "schemas",
    "scripts",
    "src",
    "suites",
    "worker",
}
_PRIVATE_GRADER = "tasks/smoke/missing-null/grader"
_PRIVATE_TEST_DIRECTORIES = ("tests/unit", "tests/contract")


class RepositoryProjectionError(RuntimeError):
    """The checkout is neither the closed evaluator nor the public projection."""


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _safe_repository_path(raw_path: bytes) -> str:
    try:
        path = raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RepositoryProjectionError("Git index contains a non-UTF-8 path") from exc
    parsed = PurePosixPath(path)
    if (
        not path
        or parsed.is_absolute()
        or parsed.as_posix() != path
        or "\\" in path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise RepositoryProjectionError("Git index contains an unsafe path")
    return path


def parse_git_index_entries(raw: bytes) -> dict[str, str]:
    """Parse a complete NUL-delimited `git ls-files --stage` result."""

    if type(raw) is not bytes:
        raise RepositoryProjectionError("Git index listing is not bytes")
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if separator != b"\t":
            raise RepositoryProjectionError("Git index contains a malformed record")
        try:
            mode, object_id, stage = metadata.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError) as exc:
            raise RepositoryProjectionError(
                "Git index contains malformed object metadata"
            ) from exc
        path = _safe_repository_path(raw_path)
        if (
            mode not in {"100644", "100755"}
            or not re.fullmatch(r"[0-9a-f]{40}", object_id)
            or stage != "0"
            or path in entries
        ):
            raise RepositoryProjectionError(
                "Git index contains a non-regular, non-stage-0, or duplicate entry"
            )
        entries[path] = mode
    return entries


def _git_index_entries(root: Path, pathspec: str) -> dict[str, str]:
    raw = subprocess.run(
        ["git", "ls-files", "--stage", "-z", "--", pathspec],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return parse_git_index_entries(raw)


def _require_clean_paths(root: Path, *pathspecs: str) -> None:
    status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            *pathspecs,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    if status:
        raise RepositoryProjectionError("public operational paths differ from the Git index")


def _require_regular_worktree_files(root: Path, entries: dict[str, str]) -> None:
    for relative in entries:
        try:
            metadata = (root / relative).lstat()
        except FileNotFoundError as exc:
            raise RepositoryProjectionError(
                "public operational overlay is missing a worktree file"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise RepositoryProjectionError(
                "public operational overlay contains a non-regular worktree entry"
            )


def is_public_source_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    if len(parsed.parts) == 1:
        return parsed.name in PUBLIC_SOURCE_ROOT_FILES
    if parsed.parts[0] in PUBLIC_SOURCE_TREES:
        return True
    return (
        parsed.parts[0] == "tasks"
        and "public" in parsed.parts[1:-1]
        and "grader" not in parsed.parts[1:]
    )


def validate_public_projection(root: Path) -> None:
    root = root.resolve(strict=True)
    forbidden = (_PRIVATE_GRADER, *_PRIVATE_TEST_DIRECTORIES)
    if any(_lexists(root / relative) for relative in forbidden):
        raise RepositoryProjectionError("public projection contains evaluator-private paths")

    public_task = root / "tasks/smoke/missing-null/public"
    try:
        public_task_mode = public_task.lstat().st_mode
    except FileNotFoundError as exc:
        raise RepositoryProjectionError("public projection lacks the smoke task") from exc
    if not stat.S_ISDIR(public_task_mode) or stat.S_ISLNK(public_task_mode):
        raise RepositoryProjectionError("public smoke-task projection is not a real directory")

    github_entries = _git_index_entries(root, ".github")
    test_entries = _git_index_entries(root, "tests")
    if github_entries != PUBLIC_OPERATIONAL_OVERLAY:
        raise RepositoryProjectionError("GitHub operational overlay is not exactly closed")
    if test_entries != PUBLIC_TEST_OVERLAY:
        raise RepositoryProjectionError("test operational overlay is not exactly closed")

    all_entries = _git_index_entries(root, ".")
    operational_paths = set(PUBLIC_OPERATIONAL_OVERLAY) | set(PUBLIC_TEST_OVERLAY)
    unexpected = sorted(
        relative
        for relative in all_entries
        if relative not in operational_paths and not is_public_source_path(relative)
    )
    if unexpected:
        raise RepositoryProjectionError(
            f"public Git index contains paths outside the source allowlist: {unexpected!r}"
        )

    task_entries = {
        path: mode for path, mode in all_entries.items() if path.startswith("tasks/")
    }
    if task_entries != PUBLIC_SMOKE_TASK:
        raise RepositoryProjectionError(
            "public smoke-task Git index is not exactly closed"
        )

    _require_regular_worktree_files(root, all_entries)
    _require_clean_paths(root, ".")


def validate_evaluator_projection(root: Path) -> None:
    root = root.resolve(strict=True)
    required_directories = (_PRIVATE_GRADER, *_PRIVATE_TEST_DIRECTORIES)
    for relative in required_directories:
        path = root / relative
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as exc:
            raise RepositoryProjectionError(
                "evaluator projection lacks its private grader or test suite"
            ) from exc
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            raise RepositoryProjectionError(
                "evaluator private grader or test suite is not a real directory"
            )


def validate_repository_projection(
    root: Path,
    *,
    github_actions: bool,
    github_repository: str | None,
) -> str:
    if github_actions and github_repository == PUBLIC_GITHUB_REPOSITORY:
        validate_public_projection(root)
        return "public"
    if _lexists(root / _PRIVATE_GRADER):
        validate_evaluator_projection(root)
        return "evaluator"
    validate_public_projection(root)
    return "public"


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    projection = validate_repository_projection(
        root,
        github_actions=os.environ.get("GITHUB_ACTIONS") == "true",
        github_repository=os.environ.get("GITHUB_REPOSITORY"),
    )
    print(f"validated {projection} repository projection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
