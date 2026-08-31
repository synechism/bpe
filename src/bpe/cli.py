"""Command-line interface for tasks, corpora, scoring, replay, and reporting."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from bpe.admission import AdmissionAttempt, AdmissionPlan, AdmissionReport, admit_task
from bpe.aggregate import aggregate_attempts
from bpe.canonical import (
    canonical_data,
    canonical_json_bytes,
    sha256_file,
    sha256_json,
    strict_json_loads,
)
from bpe.capabilities import probe_capabilities
from bpe.corpus import (
    CorpusAuditPolicy,
    CorpusAuditReport,
    audit_corpus,
    corpus_audit_report_sha256,
    load_corpus,
)
from bpe.grading import score_evidence
from bpe.job import build_evaluation_plan, load_evaluation_job_bundle
from bpe.models import (
    AttemptRecord,
    EvaluationEvidence,
    ExperimentManifest,
    ReplayAnchorRegistry,
    RewardPolicy,
    ScoringContract,
    SuiteManifest,
)
from bpe.replay import rescore_replay, verify_replay
from bpe.schemas import JSON_SCHEMAS
from bpe.task import (
    TaskBundleError,
    build_scoring_contract,
    lint_task,
    load_task_bundle,
)

ModelT = TypeVar("ModelT", bound=BaseModel)
_MAX_CLI_JSON_BYTES = 64 * 1024 * 1024


def _print_json(value: BaseModel | Any) -> None:
    print(json.dumps(canonical_data(value), indent=2, sort_keys=True, ensure_ascii=False))


def _read_json_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect JSON input {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"JSON input is missing, not a file, or a symlink: {path}")
    if before.st_size > _MAX_CLI_JSON_BYTES:
        raise ValueError(f"JSON input exceeds the 64 MiB CLI limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError(f"JSON input changed while it was being opened: {path}")
            content = handle.read(_MAX_CLI_JSON_BYTES + 1)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError(f"cannot read JSON input {path}: {exc}") from exc
    if len(content) > _MAX_CLI_JSON_BYTES:
        raise ValueError(f"JSON input exceeds the 64 MiB CLI limit: {path}")
    if len(content) != opened.st_size or (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ):
        raise ValueError(f"JSON input changed while it was being read: {path}")
    return content


def _load(path: Path, model_type: type[ModelT]) -> ModelT:
    value = strict_json_loads(_read_json_bytes(path))
    return model_type.model_validate(value)


def _load_policy(path: Path | None) -> RewardPolicy:
    if path is not None:
        return _load(path, RewardPolicy)
    raw = resources.files("bpe").joinpath("data/reward-v1.json").read_bytes()
    return RewardPolicy.model_validate(strict_json_loads(raw))


def _task_validate(args: argparse.Namespace) -> int:
    bundle = load_task_bundle(args.task_dir)
    contract = build_scoring_contract(bundle)
    evaluation_plan = build_evaluation_plan(bundle)
    _print_json(
        {
            "task_id": bundle.public.task_id,
            "version": bundle.public.version,
            "public_sha256": bundle.public_sha256,
            "private_sha256": bundle.private_sha256,
            "bundle_sha256": bundle.bundle_sha256,
            "evaluation_plan_sha256": sha256_json(evaluation_plan),
            "scoring_contract_sha256": sha256_json(contract),
        }
    )
    return 0


def _task_lint(args: argparse.Namespace) -> int:
    issues = lint_task(load_task_bundle(args.task_dir))
    _print_json({"issues": [issue.__dict__ for issue in issues]})
    return 1 if any(issue.severity == "error" for issue in issues) else 0


def _task_admission_verify(args: argparse.Namespace) -> int:
    bundle = load_task_bundle(args.task_dir)
    contract = build_scoring_contract(bundle)
    policy = _load_policy(args.policy)
    plan = _load(args.plan, AdmissionPlan)
    attempts = [_load(path, AdmissionAttempt) for path in args.attempts]
    report = admit_task(bundle, contract, policy, plan, attempts)
    if args.report is not None:
        expected = _load(args.report, AdmissionReport)
        if expected != report:
            raise ValueError("admission report does not match deterministic verification")
    _print_json(report)
    return 0


def _corpus_audit(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.manifest)
    benchmark = load_corpus(args.benchmark)
    policy = _load(args.policy, CorpusAuditPolicy)
    report = audit_corpus(corpus, benchmark, policy)
    _print_json(report)
    return 0 if report.static_audit_passed else 1


def _corpus_verify(args: argparse.Namespace) -> int:
    expected = _load(args.report, CorpusAuditReport)
    corpus = load_corpus(args.manifest)
    benchmark = load_corpus(args.benchmark)
    policy = _load(args.policy, CorpusAuditPolicy)
    actual = audit_corpus(corpus, benchmark, policy)
    if expected != actual:
        raise ValueError("corpus audit report does not match deterministic verification")
    _print_json(
        {
            "valid": True,
            "static_audit_passed": actual.static_audit_passed,
            "report_sha256": corpus_audit_report_sha256(actual),
        }
    )
    return 0 if actual.static_audit_passed else 1


def _score(args: argparse.Namespace) -> int:
    evidence = _load(args.evidence, EvaluationEvidence)
    contract = _load(args.contract, ScoringContract)
    policy = _load_policy(args.policy)
    _print_json(score_evidence(evidence, contract, policy))
    return 0


def _replay_verify(args: argparse.Namespace) -> int:
    result = verify_replay(
        args.run_dir,
        expected_manifest_sha256=args.manifest_sha256,
    )
    _print_json(
        {
            "valid": result.valid,
            "anchored": result.anchored,
            "manifest_sha256": result.manifest_sha256,
            "errors": result.errors,
            "rescored_grade": result.rescored_grade,
        }
    )
    return 0 if result.valid else 1


def _replay_rescore(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    _print_json(
        rescore_replay(
            args.run_dir,
            policy,
            expected_manifest_sha256=args.manifest_sha256,
        )
    )
    return 0


def _job_verify(args: argparse.Namespace) -> int:
    loaded = load_evaluation_job_bundle(
        args.bundle_dir,
        expected_manifest_sha256=args.manifest_sha256,
    )
    manifest = loaded.manifest
    _print_json(
        {
            "valid": True,
            "status": manifest.status,
            "anchored": loaded.anchored,
            "manifest_sha256": loaded.manifest_sha256,
            "execution_authorized": manifest.execution_authorized,
            "authoritative": manifest.authoritative,
            "request_id": manifest.request.request_id,
            "task_id": manifest.plan.task_id,
            "environment_id": manifest.environment.environment_id,
            "expected_grader_id": manifest.expected_grader_id,
            "blob_count": len(loaded.blobs),
            "total_blob_bytes": manifest.total_blob_bytes,
        }
    )
    return 0


def _trusted_registry(
    args: argparse.Namespace,
    experiment: ExperimentManifest,
) -> ReplayAnchorRegistry | None:
    if (
        args.include_nonbenchmark
        and args.anchor_registry is None
        and args.anchor_registry_sha256 is None
    ):
        return None
    if args.anchor_registry is None or args.anchor_registry_sha256 is None:
        raise ValueError(
            "strict anchored reports require --anchor-registry and "
            "--anchor-registry-sha256"
        )
    actual_digest, _ = sha256_file(args.anchor_registry)
    if actual_digest != args.anchor_registry_sha256:
        raise ValueError(
            f"anchor registry digest mismatch: expected {args.anchor_registry_sha256}, "
            f"got {actual_digest}"
        )
    registry = _load(args.anchor_registry, ReplayAnchorRegistry)
    if args.anchor_registry.read_bytes() != canonical_json_bytes(registry):
        raise ValueError("anchor registry must use canonical JSON bytes")
    if registry.experiment_manifest_sha256 != sha256_json(experiment):
        raise ValueError("anchor registry does not bind the supplied experiment manifest")
    return registry


def _report(args: argparse.Namespace) -> int:
    suite = _load(args.suite, SuiteManifest)
    experiment = _load(args.experiment, ExperimentManifest)
    records = [_load(path, AttemptRecord) for path in args.attempts]
    _print_json(
        aggregate_attempts(
            records,
            suite,
            experiment,
            k=args.k,
            include_nonbenchmark=args.include_nonbenchmark,
            bootstrap_samples=args.bootstrap_samples,
            bootstrap_seed=args.bootstrap_seed,
            trusted_replay_registry=_trusted_registry(args, experiment),
            trusted_replay_registry_sha256=args.anchor_registry_sha256,
        )
    )
    return 0


def _capabilities(_args: argparse.Namespace) -> int:
    _print_json(probe_capabilities())
    return 0


def _schema_list(_args: argparse.Namespace) -> int:
    _print_json({"schemas": sorted(JSON_SCHEMAS)})
    return 0


def _schema_show(args: argparse.Namespace) -> int:
    _print_json(JSON_SCHEMAS[args.name].model_json_schema())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bpe")
    commands = parser.add_subparsers(dest="command", required=True)

    task = commands.add_parser("task", help="validate, lint, or verify task admission")
    task_commands = task.add_subparsers(dest="task_command", required=True)
    validate = task_commands.add_parser("validate")
    validate.add_argument("task_dir", type=Path)
    validate.set_defaults(handler=_task_validate)
    lint = task_commands.add_parser("lint")
    lint.add_argument("task_dir", type=Path)
    lint.set_defaults(handler=_task_lint)
    admission = task_commands.add_parser(
        "admission",
        help="verify a provisional dynamic-admission evidence matrix",
    )
    admission_commands = admission.add_subparsers(
        dest="admission_command",
        required=True,
    )
    admission_verify = admission_commands.add_parser("verify")
    admission_verify.add_argument("task_dir", type=Path)
    admission_verify.add_argument("attempts", nargs="+", type=Path)
    admission_verify.add_argument("--plan", type=Path, required=True)
    admission_verify.add_argument("--report", type=Path)
    admission_verify.add_argument("--policy", type=Path)
    admission_verify.set_defaults(handler=_task_admission_verify)

    corpus = commands.add_parser(
        "corpus",
        help="run or verify the provisional static contamination audit",
    )
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_audit = corpus_commands.add_parser("audit")
    corpus_audit.add_argument("manifest", type=Path)
    corpus_audit.add_argument("--benchmark", type=Path, required=True)
    corpus_audit.add_argument("--policy", type=Path, required=True)
    corpus_audit.set_defaults(handler=_corpus_audit)
    corpus_verify = corpus_commands.add_parser("verify")
    corpus_verify.add_argument("report", type=Path)
    corpus_verify.add_argument("--manifest", type=Path, required=True)
    corpus_verify.add_argument("--benchmark", type=Path, required=True)
    corpus_verify.add_argument("--policy", type=Path, required=True)
    corpus_verify.set_defaults(handler=_corpus_verify)

    score = commands.add_parser("score", help="score immutable evidence")
    score.add_argument("evidence", type=Path)
    score.add_argument("--contract", type=Path, required=True)
    score.add_argument(
        "--policy",
        type=Path,
        help="reward policy JSON; defaults to the packaged reward-v1 policy",
    )
    score.set_defaults(handler=_score)

    replay = commands.add_parser("replay", help="verify or rescore a replay bundle")
    replay_commands = replay.add_subparsers(dest="replay_command", required=True)
    verify = replay_commands.add_parser("verify")
    verify.add_argument("run_dir", type=Path)
    verify.add_argument("--manifest-sha256")
    verify.set_defaults(handler=_replay_verify)
    rescore = replay_commands.add_parser("rescore")
    rescore.add_argument("run_dir", type=Path)
    rescore.add_argument("--policy", type=Path)
    rescore.add_argument("--manifest-sha256")
    rescore.set_defaults(handler=_replay_rescore)

    job = commands.add_parser(
        "job",
        help="verify a prepared, non-executable evaluation job bundle",
    )
    job_commands = job.add_subparsers(dest="job_command", required=True)
    job_verify = job_commands.add_parser("verify")
    job_verify.add_argument("bundle_dir", type=Path)
    job_verify.add_argument("--manifest-sha256")
    job_verify.set_defaults(handler=_job_verify)

    report = commands.add_parser(
        "report",
        help="aggregate a frozen Phase 0 experiment (always nonofficial)",
    )
    report.add_argument("attempts", nargs="+", type=Path)
    report.add_argument("--suite", type=Path, required=True)
    report.add_argument("--experiment", type=Path, required=True)
    report.add_argument("--anchor-registry", type=Path)
    report.add_argument("--anchor-registry-sha256")
    report.add_argument("--k", type=int, default=1)
    report.add_argument("--include-nonbenchmark", action="store_true")
    report.add_argument("--bootstrap-samples", type=int, default=2000)
    report.add_argument("--bootstrap-seed", type=int, default=0)
    report.set_defaults(handler=_report)

    capabilities = commands.add_parser("capabilities", help="probe this host honestly")
    capabilities.set_defaults(handler=_capabilities)

    schema = commands.add_parser(
        "schema",
        help="list or print published JSON contracts",
    )
    schema_commands = schema.add_subparsers(dest="schema_command", required=True)
    schema_list = schema_commands.add_parser("list")
    schema_list.set_defaults(handler=_schema_list)
    schema_show = schema_commands.add_parser("show")
    schema_show.add_argument("name", choices=sorted(JSON_SCHEMAS))
    schema_show.set_defaults(handler=_schema_show)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, ValidationError, TaskBundleError) as exc:
        print(f"bpe: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
