"""Aggregate complete, frozen benchmark runs without hiding invalid samples."""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from collections.abc import Callable, Hashable, Iterable, Sequence
from itertools import pairwise
from typing import Literal, TypeVar

from bpe.canonical import sha256_json
from bpe.models import (
    AttemptRecord,
    BenchmarkReport,
    ExperimentManifest,
    Origin,
    ReplayAnchorRegistry,
    SliceScore,
    Stage,
    SuiteManifest,
    SuiteTask,
    TrainingSeedScore,
)

T = TypeVar("T", bound=Hashable)


def pass_at_k_estimate(n: int, c: int, k: int) -> float:
    """Return the standard unbiased pass@k estimator."""

    if not 0 <= c <= n:
        raise ValueError("successful samples must be between zero and n")
    if not 1 <= k <= n:
        raise ValueError("k must be between one and n")
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


def _single_value(
    records: Sequence[AttemptRecord],
    label: str,
    getter: Callable[[AttemptRecord], T],
) -> T:
    values = {getter(record) for record in records}
    if len(values) != 1:
        raise ValueError(f"attempts mix {label}: {sorted(str(value) for value in values)}")
    return next(iter(values))


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return ordered[lower_index]
    remainder = position - lower_index
    return ordered[lower_index] * (1.0 - remainder) + ordered[upper_index] * remainder


def _cluster_bootstrap_interval(
    scores_by_seed: dict[int, dict[str, float]],
    suite_tasks: Sequence[SuiteTask],
    *,
    samples: int,
    seed: int,
) -> tuple[float, float]:
    """Bayesian cluster bootstrap with shared cluster weights across root causes."""

    strata: dict[str, list[SuiteTask]] = defaultdict(list)
    root_task_counts: Counter[str] = Counter()
    for task in suite_tasks:
        stratum = task.root_cause or "generation"
        strata[stratum].append(task)
        root_task_counts[stratum] += 1

    rng = random.Random(seed)
    replicates: list[float] = []
    total_task_count = len(suite_tasks)
    cluster_ids = sorted({task.cluster_id for task in suite_tasks})
    training_seeds = sorted(scores_by_seed)
    for _ in range(samples):
        # A shared weight preserves covariance when one original program has mutations in
        # several root-cause strata. Exponential weights implement a Bayesian bootstrap
        # without producing empty strata.
        cluster_weights = {cluster_id: rng.expovariate(1.0) for cluster_id in cluster_ids}
        seed_weights = {
            training_seed: rng.expovariate(1.0) for training_seed in training_seeds
        }
        weighted_sum = 0.0
        for root_cause in sorted(strata):
            tasks = strata[root_cause]
            denominator = sum(
                cluster_weights[task.cluster_id] * seed_weights[training_seed]
                for task in tasks
                for training_seed in training_seeds
            )
            root_mean = (
                sum(
                    cluster_weights[task.cluster_id]
                    * seed_weights[training_seed]
                    * scores_by_seed[training_seed][task.task_id]
                    for task in tasks
                    for training_seed in training_seeds
                )
                / denominator
            )
            weighted_sum += root_mean * root_task_counts[root_cause]
        replicates.append(weighted_sum / total_task_count)

    return (_percentile(replicates, 0.025), _percentile(replicates, 0.975))


def _slice_scores(
    task_scores: dict[str, float],
    suite_tasks: Sequence[SuiteTask],
    getter: Callable[[SuiteTask], str],
) -> tuple[SliceScore, ...]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for task in suite_tasks:
        grouped[getter(task)].append(task_scores[task.task_id])
    return tuple(
        SliceScore(
            name=name,
            task_count=len(scores),
            pass_at_k=sum(scores) / len(scores),
        )
        for name, scores in sorted(grouped.items())
    )


def _validate_run_identity(
    records: Sequence[AttemptRecord],
    suite: SuiteManifest,
    experiment: ExperimentManifest,
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    Literal["none", "raw", "bpfix"],
    str,
]:
    experiment_id = _single_value(records, "experiment IDs", lambda item: item.experiment_id)
    model_id = _single_value(records, "model IDs", lambda item: item.model_id)
    model_artifact_sha256 = _single_value(
        records,
        "model artifact digests",
        lambda item: item.model_artifact_sha256,
    )
    sampling_config_sha256 = _single_value(
        records,
        "sampling configurations",
        lambda item: item.sampling_config_sha256,
    )
    grader_id = _single_value(records, "grader IDs", lambda item: item.grade.grader_id)
    reward_policy_id = _single_value(
        records, "reward policy IDs", lambda item: item.grade.policy_id
    )
    reward_policy_sha256 = _single_value(
        records,
        "reward policy digests",
        lambda item: item.reward_policy_sha256,
    )
    environment_id = _single_value(
        records, "environment IDs", lambda item: item.evidence.request.environment_id
    )
    diagnostic_condition = _single_value(
        records,
        "diagnostic conditions",
        lambda item: item.evidence.request.diagnostic_condition,
    )
    environment_sha256 = _single_value(
        records,
        "environment fingerprints",
        lambda item: sha256_json(item.evidence.environment),
    )
    harness_commit = _single_value(
        records,
        "harness commits",
        lambda item: item.evidence.harness_commit,
    )
    suite_id = _single_value(
        records, "suite IDs", lambda item: item.evidence.request.suite_id
    )
    suite_digest = sha256_json(suite)
    recorded_suite_digest = _single_value(
        records,
        "suite manifest digests",
        lambda item: item.evidence.request.suite_manifest_sha256,
    )
    experiment_digest = sha256_json(experiment)
    recorded_experiment_id = _single_value(
        records,
        "request experiment IDs",
        lambda item: item.evidence.request.experiment_id,
    )
    recorded_experiment_digest = _single_value(
        records,
        "experiment manifest digests",
        lambda item: item.evidence.request.experiment_manifest_sha256,
    )

    if suite_id != suite.suite_id:
        raise ValueError(f"attempt suite {suite_id!r} does not match {suite.suite_id!r}")
    if recorded_suite_digest != suite_digest:
        raise ValueError("attempts do not bind the supplied frozen suite manifest")
    if environment_id != suite.environment_id:
        raise ValueError(
            f"attempt environment {environment_id!r} does not match "
            f"suite environment {suite.environment_id!r}"
        )
    if (
        experiment.suite_id != suite.suite_id
        or experiment.suite_manifest_sha256 != suite_digest
    ):
        raise ValueError("experiment manifest does not bind the supplied frozen suite")
    if (
        recorded_experiment_id != experiment.experiment_id
        or experiment_id != experiment.experiment_id
    ):
        raise ValueError("attempts do not match the supplied experiment identity")
    if recorded_experiment_digest != experiment_digest:
        raise ValueError("attempts do not bind the supplied frozen experiment manifest")
    if (
        model_id != experiment.model_id
        or model_artifact_sha256 != experiment.model_artifact_sha256
        or sampling_config_sha256 != experiment.sampling_config_sha256
        or diagnostic_condition != experiment.diagnostic_condition
        or reward_policy_id != experiment.reward_policy_id
        or reward_policy_sha256 != experiment.reward_policy_sha256
        or environment_sha256 != experiment.environment_sha256
        or harness_commit != experiment.harness_commit
        or grader_id != experiment.expected_grader_id
    ):
        raise ValueError("attempt run configuration does not match the experiment manifest")
    return (
        experiment_id,
        model_id,
        sampling_config_sha256,
        grader_id,
        reward_policy_id,
        environment_id,
        diagnostic_condition,
        suite_digest,
    )


def _validate_attempt_membership(
    records: Sequence[AttemptRecord],
    suite: SuiteManifest,
    experiment: ExperimentManifest,
) -> None:
    tasks_by_id = {task.task_id: task for task in suite.tasks}
    seed_plans = {plan.training_seed: plan for plan in experiment.seed_plans}
    expected_seed_set = set(seed_plans)
    seen_samples: set[tuple[str, int, int, int]] = set()
    seen_request_ids: set[str] = set()
    seen_replays: set[str] = set()
    seen_turn_zero_seeds: set[tuple[str, int, int]] = set()
    episodes_by_sample: dict[tuple[str, int, int], str] = {}
    episode_records: dict[tuple[str, int, int], list[AttemptRecord]] = defaultdict(list)

    for record in records:
        task = tasks_by_id.get(record.task_id)
        if task is None:
            raise ValueError(f"attempt references task outside frozen suite: {record.task_id}")
        expected_identity = (
            task.task_version,
            task.task_bundle_sha256,
            task.scoring_contract_sha256,
            task.family,
            task.root_cause,
            task.program_type,
            task.cluster_id,
        )
        actual_identity = (
            record.task_version,
            record.task_bundle_sha256,
            record.grade.contract_sha256,
            record.family,
            record.root_cause,
            record.program_type,
            record.cluster_id,
        )
        if actual_identity != expected_identity:
            raise ValueError(f"attempt metadata does not match frozen suite task {record.task_id}")
        if record.training_seed not in expected_seed_set:
            raise ValueError(
                f"attempt uses undeclared training seed {record.training_seed} for {record.task_id}"
            )
        seed_plan = seed_plans[record.training_seed]
        if record.checkpoint_id != seed_plan.checkpoint_id:
            raise ValueError(
                f"attempt checkpoint does not match training seed {record.training_seed}"
            )
        if record.checkpoint_artifact_sha256 != seed_plan.checkpoint_artifact_sha256:
            raise ValueError(
                f"attempt checkpoint digest does not match training seed {record.training_seed}"
            )

        sample_identity = (
            record.task_id,
            record.training_seed,
            record.sample_index,
            record.turn_index,
        )
        if sample_identity in seen_samples:
            raise ValueError(f"duplicate sample identity: {sample_identity}")
        seen_samples.add(sample_identity)
        if record.evidence.request.request_id in seen_request_ids:
            raise ValueError(f"duplicate request ID: {record.evidence.request.request_id}")
        seen_request_ids.add(record.evidence.request.request_id)
        if record.replay_manifest_sha256 in seen_replays:
            raise ValueError(
                f"duplicate replay manifest: {record.replay_manifest_sha256}"
            )
        seen_replays.add(record.replay_manifest_sha256)
        if record.turn_index == 0:
            if record.sample_index >= len(seed_plan.generation_seeds):
                raise ValueError(
                    f"sample index is outside the experiment seed plan: {sample_identity}"
                )
            if record.generation_seed != seed_plan.generation_seeds[record.sample_index]:
                raise ValueError(
                    f"generation seed does not match the experiment plan: {sample_identity}"
                )
            generation_identity = (
                record.task_id,
                record.training_seed,
                record.generation_seed,
            )
            if generation_identity in seen_turn_zero_seeds:
                raise ValueError(f"duplicate turn-zero generation seed: {generation_identity}")
            seen_turn_zero_seeds.add(generation_identity)

        episode_identity = (record.task_id, record.training_seed, record.sample_index)
        prior_episode = episodes_by_sample.setdefault(episode_identity, record.episode_id)
        if prior_episode != record.episode_id:
            raise ValueError(f"sample {episode_identity} is split across episode IDs")
        episode_records[episode_identity].append(record)

    for episode_identity, episode in episode_records.items():
        ordered = sorted(episode, key=lambda record: record.turn_index)
        turns = [record.turn_index for record in ordered]
        if turns != list(range(len(turns))):
            raise ValueError(f"episode {episode_identity} has non-contiguous turns")
        for previous, current in pairwise(ordered):
            if current.evidence.request.parent_request_id != previous.evidence.request.request_id:
                raise ValueError(f"episode {episode_identity} has broken parent linkage")


def _eligible_turn_zero(
    records: Sequence[AttemptRecord],
    *,
    include_nonbenchmark: bool,
    trusted_replay_registry: ReplayAnchorRegistry | None,
) -> list[AttemptRecord]:
    if include_nonbenchmark:
        return [record for record in records if record.turn_index == 0]
    turn_zero = [record for record in records if record.turn_index == 0]
    non_microvm = [record for record in turn_zero if record.evidence.origin != Origin.MICROVM]
    if non_microvm:
        raise ValueError("strict anchored aggregation accepts only microVM turn-zero evidence")
    if trusted_replay_registry is None:
        raise ValueError("strict anchored aggregation requires a replay-anchor registry")
    anchors = {
        anchor.manifest_sha256: anchor for anchor in trusted_replay_registry.anchors
    }
    unanchored = [
        record
        for record in turn_zero
        if (anchor := anchors.get(record.replay_manifest_sha256)) is None
        or anchor.evidence_sha256 != record.grade.evidence_sha256
        or anchor.grade_sha256 != sha256_json(record.grade)
        or anchor.contract_sha256 != record.grade.contract_sha256
        or anchor.policy_sha256 != record.reward_policy_sha256
    ]
    if unanchored:
        identities = sorted(
            (record.task_id, record.training_seed, record.sample_index)
            for record in unanchored
        )
        raise ValueError(
            f"strict aggregation requires externally anchored replays: {identities}"
        )
    return turn_zero


def _task_scores(
    eligible: Sequence[AttemptRecord],
    suite: SuiteManifest,
    expected_training_seeds: tuple[int, ...],
    k: int,
    expected_samples_per_task_seed: int,
) -> tuple[dict[str, float], dict[int, dict[str, float]]]:
    grouped: dict[tuple[str, int], list[AttemptRecord]] = defaultdict(list)
    for record in eligible:
        grouped[(record.task_id, record.training_seed)].append(record)

    result: dict[str, float] = {}
    by_seed: dict[int, dict[str, float]] = {
        training_seed: {} for training_seed in expected_training_seeds
    }
    for task in suite.tasks:
        seed_scores: list[float] = []
        for training_seed in expected_training_seeds:
            attempts = grouped.get((task.task_id, training_seed), [])
            if any(not attempt.grade.comparable for attempt in attempts):
                raise ValueError(
                    f"infrastructure failure makes {task.task_id}/seed-{training_seed} incomplete"
                )
            if len(attempts) != expected_samples_per_task_seed:
                raise ValueError(
                    f"{task.task_id}/seed-{training_seed} has {len(attempts)} "
                    "eligible attempts; the frozen sample design requires exactly "
                    f"{expected_samples_per_task_seed}"
                )

            sample_indices = sorted(attempt.sample_index for attempt in attempts)
            if sample_indices != list(range(len(sample_indices))):
                raise ValueError(
                    f"{task.task_id}/seed-{training_seed} sample indices must be contiguous "
                    "from zero; missing samples cannot be silently dropped"
                )
            successes = sum(attempt.grade.strict_success is True for attempt in attempts)
            score = pass_at_k_estimate(len(attempts), successes, k)
            seed_scores.append(score)
            by_seed[training_seed][task.task_id] = score
        result[task.task_id] = sum(seed_scores) / len(seed_scores)
    return result, by_seed


def aggregate_attempts(
    records: Iterable[AttemptRecord],
    suite: SuiteManifest,
    experiment: ExperimentManifest,
    *,
    k: int = 1,
    include_nonbenchmark: bool = False,
    bootstrap_samples: int = 2000,
    bootstrap_seed: int = 0,
    trusted_replay_registry: ReplayAnchorRegistry | None = None,
    trusted_replay_registry_sha256: str | None = None,
) -> BenchmarkReport:
    """Aggregate a complete suite or fail rather than publish a partial result."""

    if isinstance(k, bool) or k < 1:
        raise ValueError("k must be a positive integer")
    if isinstance(bootstrap_samples, bool) or bootstrap_samples < 1:
        raise ValueError("bootstrap_samples must be a positive integer")
    if isinstance(bootstrap_seed, bool) or bootstrap_seed < 0:
        raise ValueError("bootstrap_seed must be a non-negative integer")
    frozen_suite = SuiteManifest.model_validate(suite.model_dump(mode="python"))
    frozen_experiment = ExperimentManifest.model_validate(
        experiment.model_dump(mode="python")
    )
    frozen_registry = (
        ReplayAnchorRegistry.model_validate(
            trusted_replay_registry.model_dump(mode="python")
        )
        if trusted_replay_registry is not None
        else None
    )
    if (
        frozen_registry is not None
        and frozen_registry.experiment_manifest_sha256 != sha256_json(frozen_experiment)
    ):
        raise ValueError("replay-anchor registry does not bind the experiment manifest")
    registry_digest = sha256_json(frozen_registry) if frozen_registry is not None else None
    if not include_nonbenchmark and (
        frozen_registry is None or trusted_replay_registry_sha256 is None
    ):
        raise ValueError(
            "strict anchored aggregation requires a registry and its external trusted digest"
        )
    if trusted_replay_registry_sha256 is not None and (
        registry_digest != trusted_replay_registry_sha256
    ):
        raise ValueError("replay-anchor registry does not match its external trusted digest")
    if k not in frozen_experiment.reported_k:
        raise ValueError("k was not predeclared in the frozen experiment manifest")
    seeds = tuple(sorted(plan.training_seed for plan in frozen_experiment.seed_plans))
    expected_samples_per_task_seed = frozen_experiment.samples_per_task_seed
    all_records = [
        AttemptRecord.model_validate(record.model_dump(mode="python")) for record in records
    ]
    if not all_records:
        raise ValueError("cannot aggregate an empty attempt set")

    (
        experiment_id,
        model_id,
        sampling_config_sha256,
        grader_id,
        reward_policy_id,
        environment_id,
        diagnostic_condition,
        suite_digest,
    ) = _validate_run_identity(all_records, frozen_suite, frozen_experiment)
    _validate_attempt_membership(all_records, frozen_suite, frozen_experiment)

    eligible = _eligible_turn_zero(
        all_records,
        include_nonbenchmark=include_nonbenchmark,
        trusted_replay_registry=frozen_registry,
    )
    scores_by_task, scores_by_seed = _task_scores(
        eligible,
        frozen_suite,
        seeds,
        k,
        expected_samples_per_task_seed,
    )
    pass_at_k = sum(scores_by_task.values()) / len(scores_by_task)
    by_root_cause = (
        _slice_scores(
            scores_by_task,
            frozen_suite.tasks,
            lambda task: task.root_cause or "generation",
        )
        if frozen_suite.family == "repair"
        else ()
    )
    by_program_type = _slice_scores(
        scores_by_task, frozen_suite.tasks, lambda task: task.program_type
    )
    root_cause_macro = (
        sum(score.pass_at_k for score in by_root_cause if score.pass_at_k is not None)
        / len(by_root_cause)
        if by_root_cause
        else None
    )
    training_seed_results = tuple(
        TrainingSeedScore(
            training_seed=plan.training_seed,
            checkpoint_id=plan.checkpoint_id,
            checkpoint_artifact_sha256=plan.checkpoint_artifact_sha256,
            task_count=len(frozen_suite.tasks),
            pass_at_k=(
                sum(scores_by_seed[plan.training_seed].values())
                / len(scores_by_seed[plan.training_seed])
            ),
        )
        for plan in sorted(frozen_experiment.seed_plans, key=lambda item: item.training_seed)
    )

    failures: Counter[Stage] = Counter(
        record.grade.first_failure
        for record in eligible
        if record.grade.first_failure is not None
    )
    notes = (
        "Every frozen-suite task and declared training seed has the exact frozen sample count.",
        "Only independent turn-0 attempts contribute to pass@k; repair turns are excluded.",
        (
            "Replay manifests were checked against an externally supplied registry and the "
            "pinned microVM identity."
            if not include_nonbenchmark
            else "This diagnostic report may include non-microVM or unanchored evidence."
        ),
        (
            "Phase 0 cannot produce official results because it has neither authoritative "
            "kernel execution nor authenticated evaluator attestations."
        ),
        "The Bayesian interval shares original-program cluster weights across strata.",
    )
    return BenchmarkReport(
        official=False,
        experiment_id=experiment_id,
        experiment_manifest_sha256=sha256_json(frozen_experiment),
        replay_anchor_registry_sha256=(
            registry_digest
        ),
        suite_id=frozen_suite.suite_id,
        suite_manifest_sha256=suite_digest,
        strict_policy_id=frozen_suite.strict_policy_id,
        family=frozen_suite.family,
        grader_id=grader_id,
        reward_policy_id=reward_policy_id,
        reward_policy_sha256=frozen_experiment.reward_policy_sha256,
        environment_id=environment_id,
        environment_sha256=frozen_experiment.environment_sha256,
        harness_commit=frozen_experiment.harness_commit,
        diagnostic_condition=diagnostic_condition,
        model_id=model_id,
        model_artifact_sha256=frozen_experiment.model_artifact_sha256,
        sampling_config_sha256=sampling_config_sha256,
        k=k,
        samples_per_task_seed=expected_samples_per_task_seed,
        eligible_task_count=len(scores_by_task),
        eligible_training_seed_count=len(seeds),
        training_seeds=seeds,
        eligible_attempt_count=len(eligible),
        excluded_attempt_count=len(all_records) - len(eligible),
        pass_at_k=pass_at_k,
        root_cause_macro_pass_at_k=root_cause_macro,
        bootstrap_95=_cluster_bootstrap_interval(
            scores_by_seed,
            frozen_suite.tasks,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        ),
        bootstrap_method=(
            "training-seed-and-root-cause-cluster-bayesian"
            if frozen_suite.family == "repair"
            else "training-seed-and-cluster-bayesian"
        ),
        bootstrap_samples=bootstrap_samples,
        bootstrap_seed=bootstrap_seed,
        by_root_cause=by_root_cause,
        by_program_type=by_program_type,
        training_seed_results=training_seed_results,
        failure_stage_counts=dict(failures),
        notes=notes,
    )
