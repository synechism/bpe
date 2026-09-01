"""Central registry for every published JSON contract."""

from __future__ import annotations

from pydantic import BaseModel

from bpe.admission import AdmissionAttempt, AdmissionPlan, AdmissionReport
from bpe.capabilities import WorkerCapabilities
from bpe.cgroup import JSON_SCHEMAS as CGROUP_JSON_SCHEMAS
from bpe.corpus import CorpusAuditPolicy, CorpusAuditReport, CorpusManifest
from bpe.dispatch import JSON_SCHEMAS as DISPATCH_JSON_SCHEMAS
from bpe.inert_artifact import JSON_SCHEMAS as INERT_ARTIFACT_JSON_SCHEMAS
from bpe.inert_fixture import JSON_SCHEMAS as INERT_FIXTURE_JSON_SCHEMAS
from bpe.inert_launch import JSON_SCHEMAS as INERT_LAUNCH_JSON_SCHEMAS
from bpe.inert_native_qualification import (
    JSON_SCHEMAS as INERT_NATIVE_QUALIFICATION_JSON_SCHEMAS,
)
from bpe.ingress import JSON_SCHEMAS as INGRESS_JSON_SCHEMAS
from bpe.job import EvaluationJobManifest, EvaluationPlan
from bpe.models import JSON_SCHEMAS as CORE_JSON_SCHEMAS
from bpe.oracle import JSON_SCHEMAS as ORACLE_JSON_SCHEMAS
from bpe.qualification import JSON_SCHEMAS as QUALIFICATION_JSON_SCHEMAS
from bpe.worker_protocol import CapabilitiesRequest, WorkerResponseEnvelope

JSON_SCHEMAS: dict[str, type[BaseModel]] = {
    **CORE_JSON_SCHEMAS,
    **CGROUP_JSON_SCHEMAS,
    **DISPATCH_JSON_SCHEMAS,
    **INGRESS_JSON_SCHEMAS,
    **INERT_ARTIFACT_JSON_SCHEMAS,
    **INERT_FIXTURE_JSON_SCHEMAS,
    **INERT_LAUNCH_JSON_SCHEMAS,
    **INERT_NATIVE_QUALIFICATION_JSON_SCHEMAS,
    **ORACLE_JSON_SCHEMAS,
    **QUALIFICATION_JSON_SCHEMAS,
    "admission-plan-v1.json": AdmissionPlan,
    "admission-attempt-v1.json": AdmissionAttempt,
    "admission-report-v1.json": AdmissionReport,
    "corpus-manifest-v1.json": CorpusManifest,
    "corpus-audit-policy-v1.json": CorpusAuditPolicy,
    "corpus-audit-report-v1.json": CorpusAuditReport,
    "evaluation-plan-v1.json": EvaluationPlan,
    "evaluation-job-v1.json": EvaluationJobManifest,
    "worker-capabilities-v1.json": WorkerCapabilities,
    "worker-request-v1.json": CapabilitiesRequest,
    "worker-response-v1.json": WorkerResponseEnvelope,
}

if len(JSON_SCHEMAS) != (
    len(CORE_JSON_SCHEMAS)
    + len(CGROUP_JSON_SCHEMAS)
    + len(DISPATCH_JSON_SCHEMAS)
    + len(INGRESS_JSON_SCHEMAS)
    + len(INERT_ARTIFACT_JSON_SCHEMAS)
    + len(INERT_FIXTURE_JSON_SCHEMAS)
    + len(INERT_LAUNCH_JSON_SCHEMAS)
    + len(INERT_NATIVE_QUALIFICATION_JSON_SCHEMAS)
    + len(ORACLE_JSON_SCHEMAS)
    + len(QUALIFICATION_JSON_SCHEMAS)
    + 11
):
    raise RuntimeError("JSON schema filenames must be unique")

__all__ = ["JSON_SCHEMAS"]
