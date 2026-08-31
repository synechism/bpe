"""Content-derived identities for grader comparability."""

from __future__ import annotations

from typing import TYPE_CHECKING

from bpe.canonical import sha256_json

if TYPE_CHECKING:
    from bpe.models import EnvironmentFingerprint, EvaluationRequest

STRICT_SCORING_POLICY_ID = "strict-success-v1"


def grader_id_for(
    request: EvaluationRequest,
    environment: EnvironmentFingerprint,
    harness_commit: str,
) -> str:
    """Bind strict scoring to the task pack, harness, and exact execution environment."""

    return sha256_json(
        {
            "schema_version": "bpe.grader-id.v1",
            "strict_scoring_policy_id": STRICT_SCORING_POLICY_ID,
            "suite_id": request.suite_id,
            "suite_manifest_sha256": request.suite_manifest_sha256,
            "environment_sha256": sha256_json(environment),
            "harness_commit": harness_commit,
        }
    )
