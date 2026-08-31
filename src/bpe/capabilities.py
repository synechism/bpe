"""Honest platform/worker capability discovery."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator

from bpe.models import FrozenModel


class WorkerCapabilities(FrozenModel):
    model_config = ConfigDict(strict=True)

    schema_version: Literal["bpe.worker-capabilities.v1"]
    platform: Annotated[str, Field(min_length=1, max_length=64)]
    architecture: Annotated[str, Field(min_length=1, max_length=64)]
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    clang_path: Annotated[str, Field(min_length=1, max_length=4096)] | None
    bpftool_path: Annotated[str, Field(min_length=1, max_length=4096)] | None
    btf_available: bool
    compiler_prerequisites_present: bool
    loader_prerequisites_present: bool
    worker_execution_implemented: Literal[False]
    can_compile_bpf: Literal[False]
    can_load_bpf: Literal[False]
    official_benchmark_eligible: Literal[False]
    reasons: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=32),
    ]

    @field_validator(
        "worker_execution_implemented",
        "can_compile_bpf",
        "can_load_bpf",
        "official_benchmark_eligible",
        mode="before",
    )
    @classmethod
    def execution_claims_are_exact_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("Phase 0 execution and eligibility claims must be false")
        return value

    @field_validator("reasons", mode="before")
    @classmethod
    def json_reasons_are_frozen(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value


def probe_capabilities() -> WorkerCapabilities:
    system = platform.system().lower()
    clang = shutil.which("clang-18")
    bpftool = shutil.which("bpftool")
    btf_available = system == "linux" and Path("/sys/kernel/btf/vmlinux").is_file()
    compiler_prerequisites = system == "linux" and clang is not None
    loader_prerequisites = system == "linux" and bpftool is not None and btf_available
    reasons: list[str] = [
        "the Phase 0 worker reports host prerequisites only; candidate compilation and "
        "loading are not implemented"
    ]
    if system != "linux":
        reasons.append("the Linux kernel verifier is unavailable on this host")
    if not clang:
        reasons.append("the pinned Clang 18 entrypoint was not found")
    if not bpftool:
        reasons.append("bpftool was not found")
    if system == "linux" and not btf_available:
        reasons.append("kernel BTF is unavailable")
    if loader_prerequisites:
        reasons.append(
            "native loader prerequisites are present, but native runs would be "
            "nonofficial diagnostics only"
        )
    return WorkerCapabilities(
        schema_version="bpe.worker-capabilities.v1",
        platform=system,
        architecture=platform.machine(),
        kernel_release=platform.release(),
        clang_path=clang,
        bpftool_path=bpftool,
        btf_available=btf_available,
        compiler_prerequisites_present=compiler_prerequisites,
        loader_prerequisites_present=loader_prerequisites,
        worker_execution_implemented=False,
        can_compile_bpf=False,
        can_load_bpf=False,
        official_benchmark_eligible=False,
        reasons=tuple(reasons),
    )
