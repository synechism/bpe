"""Pure benchmark scoring and separately versioned RL reward shaping."""

from __future__ import annotations

from bpe.canonical import sha256_json
from bpe.models import (
    EvaluationEvidence,
    Grade,
    Outcome,
    RewardPolicy,
    ScoringContract,
    Stage,
    StageEvidence,
)

_INFRA_OUTCOMES = {Outcome.INFRA_ERROR, Outcome.UNSUPPORTED}


def _first_non_pass(evidence: EvaluationEvidence) -> StageEvidence | None:
    return next((stage for stage in evidence.stages if stage.outcome != Outcome.PASS), None)


def _training_reward(
    evidence: EvaluationEvidence,
    policy: RewardPolicy,
    *,
    first_failure_stage: Stage | None,
    first_failure_reason: str | None,
    explicit_hack: bool,
) -> float:
    if first_failure_stage is None:
        return policy.success_reward
    if explicit_hack or (
        first_failure_reason
        and first_failure_reason.startswith(policy.explicit_hack_reason_prefix)
    ):
        return policy.explicit_hack_reward
    if first_failure_stage == Stage.INGEST:
        return policy.ingest_failure_reward
    if first_failure_stage == Stage.COMPILE:
        return policy.compile_failure_reward
    if first_failure_stage == Stage.OBJECT_POLICY:
        return policy.object_policy_failure_reward
    if first_failure_stage == Stage.VERIFIER:
        return policy.verifier_failure_reward

    failed = next(stage for stage in evidence.stages if stage.stage == first_failure_stage)
    if first_failure_stage == Stage.FUNCTIONAL:
        return policy.functional_reward_cap * failed.required_fraction()
    if first_failure_stage == Stage.SEMANTICS:
        span = policy.semantics_reward_cap - policy.functional_reward_cap
        return policy.functional_reward_cap + span * failed.required_fraction()
    raise AssertionError(f"unhandled stage: {first_failure_stage}")


def _validate_contract(evidence: EvaluationEvidence, contract: ScoringContract) -> None:
    request = evidence.request
    if (request.task_id, request.task_version, request.task_bundle_sha256) != (
        contract.task_id,
        contract.task_version,
        contract.task_bundle_sha256,
    ):
        raise ValueError("scoring contract does not match the evidence task identity")

    expected_by_stage = {
        stage: {check.check_id: check for check in contract.checks if check.stage == stage}
        for stage in Stage
    }
    for stage_evidence in evidence.stages:
        if stage_evidence.outcome == Outcome.SKIPPED:
            continue
        expected = expected_by_stage[stage_evidence.stage]
        actual = {check.check_id: check for check in stage_evidence.checks}
        if stage_evidence.outcome in {Outcome.INFRA_ERROR, Outcome.UNSUPPORTED} and not actual:
            continue
        if set(actual) != set(expected):
            raise ValueError(
                f"{stage_evidence.stage.value} evidence check set does not match contract"
            )
        for check_id, expected_check in expected.items():
            actual_check = actual[check_id]
            if (
                actual_check.required != expected_check.required
                or actual_check.weight != expected_check.weight
            ):
                raise ValueError(f"check metadata differs from contract: {check_id}")
            for artifact_name, expected_ref in expected_check.input_artifacts.items():
                if actual_check.artifacts.get(artifact_name) != expected_ref:
                    raise ValueError(
                        f"check input artifact differs from contract: "
                        f"{check_id}/{artifact_name}"
                    )


def score_evidence(
    evidence: EvaluationEvidence,
    contract: ScoringContract,
    policy: RewardPolicy,
) -> Grade:
    """Score stored evidence without executing candidate code.

    The benchmark result is a hard conjunction. The scalar training reward is policy data
    and is intentionally not used to define benchmark success.
    """

    evidence = EvaluationEvidence.model_validate(evidence.model_dump(mode="python"))
    contract = ScoringContract.model_validate(contract.model_dump(mode="python"))
    policy = RewardPolicy.model_validate(policy.model_dump(mode="python"))
    _validate_contract(evidence, contract)

    evidence_sha256 = sha256_json(evidence)
    contract_sha256 = sha256_json(contract)
    stage_outcomes = {item.stage: item.outcome for item in evidence.stages}
    first_non_pass = _first_non_pass(evidence)

    if first_non_pass and first_non_pass.outcome in _INFRA_OUTCOMES:
        return Grade(
            policy_id=policy.policy_id,
            grader_id=evidence.grader_id,
            task_id=evidence.request.task_id,
            candidate_sha256=evidence.request.candidate.sha256,
            evidence_sha256=evidence_sha256,
            contract_sha256=contract_sha256,
            comparable=False,
            strict_success=None,
            benchmark_score=None,
            training_reward=None,
            first_failure=first_non_pass.stage,
            failure_reason=first_non_pass.reason_code,
            stage_outcomes=stage_outcomes,
        )

    success = first_non_pass is None
    first_failure_stage = first_non_pass.stage if first_non_pass else None
    first_failure_reason = first_non_pass.reason_code if first_non_pass else None
    explicit_hack = any(
        check.required
        and check.outcome != Outcome.PASS
        and check.reason_code.startswith(policy.explicit_hack_reason_prefix)
        for stage in evidence.stages
        for check in stage.checks
    )
    reward = _training_reward(
        evidence,
        policy,
        first_failure_stage=first_failure_stage,
        first_failure_reason=first_failure_reason,
        explicit_hack=explicit_hack,
    )
    return Grade(
        policy_id=policy.policy_id,
        grader_id=evidence.grader_id,
        task_id=evidence.request.task_id,
        candidate_sha256=evidence.request.candidate.sha256,
        evidence_sha256=evidence_sha256,
        contract_sha256=contract_sha256,
        comparable=True,
        strict_success=success,
        benchmark_score=1.0 if success else 0.0,
        training_reward=reward,
        first_failure=first_failure_stage,
        failure_reason=first_failure_reason,
        stage_outcomes=stage_outcomes,
    )
