"""Native Linux gate for the empty-leaf cgroup-v2 qualification boundary.

Run only as PID 1 in a disposable privileged cgroup namespace.  The script creates an
empty sibling delegation root while keeping itself in a separate manager cgroup.  It
never launches a candidate or a child fixture.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import sys
from pathlib import Path

import bpe.cgroup as cgroup_module
from bpe.canonical import canonical_data
from bpe.cgroup import LinuxCgroupV2QualificationPolicy, qualify_linux_cgroup_v2
from bpe.dispatch import ExecutionResourceProfile


def _write_control(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="ascii")


def main() -> None:
    if sys.platform != "linux" or os.getpid() != 1 or os.geteuid() != 0:
        raise RuntimeError("native cgroup probe requires Linux PID 1 with effective UID 0")

    native_architecture = platform.machine()
    arm64_override = (
        native_architecture == "aarch64"
        and os.environ.get("BPE_ALLOW_ARM64_OPENAT2_TEST") == "1"
    )
    if native_architecture != "x86_64" and not arm64_override:
        raise RuntimeError("native cgroup probe requires x86_64")
    if arm64_override:
        # This tests native cgroupfs and openat2 semantics on Docker Desktop.  Linux
        # assigns openat2 syscall 437 on both ABIs; it is not an x86-64 release gate.
        cgroup_module.platform.machine = lambda: "x86_64"

    root = Path("/sys/fs/cgroup")
    suffix = secrets.token_hex(8)
    manager = root / f"bpe-native-manager-{suffix}"
    delegate = root / f"bpe-native-delegate-{suffix}"
    manager.mkdir()
    _write_control(manager / "cgroup.procs", str(os.getpid()))
    _write_control(root / "cgroup.subtree_control", "+cpu +memory +pids")
    delegate.mkdir()
    _write_control(delegate / "cgroup.subtree_control", "+cpu +memory +pids")
    # The container has no systemd manager.  This installs the exact kernel xattr
    # convention that production checks; systemd provisioning is a separate deployment
    # obligation and the report never treats the marker as proof of provenance.
    os.setxattr(delegate, b"user.delegate", b"1")

    policy = LinuxCgroupV2QualificationPolicy(
        schema_version="bpe.linux-cgroup-v2-qualification-policy.v1",
        policy_id="native-empty-cgroup-qualification-v1",
        worker_pool_audience="native-probe-workers",
        delegated_root_id="disposable-container-delegate",
        host_platform="linux",
        host_architecture="x86_64",
        filesystem="cgroup2-v2",
        delegation_method="systemd-user.delegate-xattr-v1",
        delegated_owner="current-euid",
        delegated_root_group_other_writable=False,
        root_cgroup_type="domain",
        root_empty_required=True,
        root_without_children_required=True,
        required_controllers=("cpu", "memory", "pids"),
        subtree_control_exact=True,
        component_open_method="openat2-v1",
        resolve_beneath=True,
        resolve_no_xdev=True,
        resolve_no_symlinks=True,
        resolve_no_magiclinks=True,
        openat2_eagain_retries=3,
        leaf_name_method="random-256-bit-v1",
        memory_limit_method="memory.max-v1",
        swap_limit_method="memory.swap.max-zero-v1",
        pids_limit_method="pids.max-v1",
        cpu_limit_method="cpu.max-one-cpu-equivalent-bandwidth-v1",
        cpu_quota_us=100_000,
        cpu_period_us=100_000,
        cpu_burst_us=0,
        base_page_size_bytes=4096,
        oom_group_method="memory.oom.group-v1",
        leaf_max_depth=0,
        leaf_max_descendants=0,
        cleanup_method="cgroup.kill-events-rmdir-v1",
        cleanup_timeout_ms=5000,
        process_creation_probed=False,
        execution_permitted=False,
        candidate_access_permitted=False,
        resource_profile_fully_enforced=False,
        authoritative_ready=False,
    )
    profile = ExecutionResourceProfile(
        schema_version="bpe.execution-resource-profile.v1",
        profile_id="native-empty-cgroup-resources-v1",
        wall_timeout_ms=30_000,
        cpu_time_seconds=20,
        memory_bytes=256 * 1024 * 1024,
        swap_bytes=0,
        pids_max=32,
        open_files_max=64,
        file_size_bytes=16 * 1024 * 1024,
        stack_bytes=8 * 1024 * 1024,
        stdout_bytes=256 * 1024,
        stderr_bytes=256 * 1024,
        tmpfs_bytes=64 * 1024 * 1024,
        tmpfs_inodes=4096,
        network_enabled=False,
        core_dumps_enabled=False,
    )

    delegate_fd = os.open(delegate, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        report = qualify_linux_cgroup_v2(policy, profile, delegated_root_fd=delegate_fd)
    finally:
        os.close(delegate_fd)

    if any(entry.is_dir() for entry in delegate.iterdir()):
        raise RuntimeError("qualification left a child cgroup behind")
    delegate.rmdir()
    if (
        report.execution_started
        or report.clone3_qualified
        or report.limits_exercised
        or not report.cgroup_kill_empty_write_verified
        or not report.leaf_name_removed
    ):
        raise RuntimeError("native qualification report crossed its nonexecution boundary")
    print(
        json.dumps(
            {
                "arm64_test_override": arm64_override,
                "native_architecture": native_architecture,
                "report": canonical_data(report),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
