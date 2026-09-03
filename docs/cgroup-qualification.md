# Linux cgroup-v2 empty-leaf qualification

Phase 1B.1 implements a deliberately non-executing host qualification probe. It accepts a
pre-opened systemd-delegated cgroup-v2 root, creates one random empty leaf, writes and reads
back a fixed subset of an `ExecutionResourceProfile`, exercises the cleanup path while the
leaf is still empty, removes the leaf, and only then returns a report.

That report is an unsigned, point-in-time local observation. It is not a durable lease on
the delegated root, a dispatch authorization, a process-containment result, or evidence
that the complete resource profile was enforced. Phase 1B.1 never creates a process and
never reads candidate or prepared-job bytes.

The public contracts are `LinuxCgroupV2QualificationPolicy`,
`LinuxCgroupV2QualificationReport`, `LinuxCgroupV2RetainedLeaf`,
`qualify_linux_cgroup_v2(...)`, and `retain_linux_cgroup_v2_leaf(...)` in `bpe.cgroup`.
Their JSON schemas are
[`linux-cgroup-v2-qualification-policy-v1.json`](../schemas/linux-cgroup-v2-qualification-policy-v1.json)
and
[`linux-cgroup-v2-qualification-report-v1.json`](../schemas/linux-cgroup-v2-qualification-report-v1.json).

## Public boundary

```python
def qualify_linux_cgroup_v2(
    policy: LinuxCgroupV2QualificationPolicy,
    resource_profile: ExecutionResourceProfile,
    *,
    delegated_root_fd: int,
) -> LinuxCgroupV2QualificationReport: ...
```

`delegated_root_fd` is a pre-opened readable directory descriptor, not a pathname. A
trusted supervisor is responsible for creating the systemd delegation, opening the exact
root intended by `delegated_root_id`, and keeping exclusive ownership of it for the call.
The ID is a deployment label; the function cannot derive or authenticate the label-to-file
descriptor mapping.

For the native orchestration boundary, `retain_linux_cgroup_v2_leaf(...)` runs the same root
admission, creation, configuration, exact readback, and post-configuration root audit but
returns a process-free retained handle instead of immediately cleaning the leaf and issuing
a report. The handle is not a qualification report, launch token, or authority grant.

The retained handle never exposes a borrowed descriptor. `duplicate_leaf_fd()` revalidates
the root metadata, cgroup-v2 filesystem, delegation marker, domain/controller/exclusivity
state, exact sole child name and inode, and retained leaf identity. Under the same handle
lock, it then requires the leaf to remain an empty, unfrozen domain with no subtree controller
or descendant and rereads all eight configured controls at their exact values. Only after
that read-only audit does it return one caller-owned close-on-exec duplicate; drift is never
rewritten or repaired during handoff. The caller must close every such duplicate before
`cleanup()`. An intentionally unclosed duplicate may remain usable after the cgroup name is
removed, but it is a stale descriptor and is never evidence that the kernel reclaimed the
cgroup object.

The function is Linux x86-64 only. It refuses other platforms or ABIs before validating
the policy, resource profile, or supplied descriptor. It also requires the pinned 24-byte
`open_how` ABI, `O_PATH`, `F_DUPFD_CLOEXEC`, and a 4096-byte host base page. There is no
`openat(2)` fallback when the exact `openat2(2)` contract is unavailable.

## Delegated-root admission

The function first pins the supplied descriptor with close-on-exec, probes the exact
`openat2(2)` contract, and independently reopens `.` beneath the pinned descriptor. The
independent directory description prevents a caller-controlled shared directory offset
from hiding entries during enumeration. It then checks all of the following before
creating a leaf:

- the descriptor is a readable directory rather than an `O_PATH` descriptor, is owned by
  the current effective UID, and is not group- or other-writable;
- `fstatfs` reports `CGROUP2_SUPER_MAGIC`;
- `fgetxattr` returns the exact systemd delegation marker `user.delegate=1`;
- `cgroup.type` is exactly `domain`;
- `cgroup.controllers` includes `cpu`, `memory`, and `pids`, while
  `cgroup.subtree_control` contains exactly those three controllers;
- `cgroup.events` reports `populated 0` and, when present, `frozen 0`;
- `cgroup.procs` and `cgroup.threads` are empty; and
- the delegated root has no child cgroups.

The `user.delegate=1` xattr is a systemd marker, not proof of a safe delegation by itself.
Ownership, permissions, filesystem identity, root type, controller availability and exact
enablement, empty process/thread state, and exclusive child state remain independent
mandatory checks. The function repeats the mutable root checks during the leaf lifecycle
and verifies the root identity, metadata, cgroup-v2 filesystem, and delegation marker
again before returning.

Every named cgroup component is opened relative to a retained descriptor with
`openat2(2)` and the combined `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`,
`RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS` flags. `EINTR` and `EAGAIN` receive at
most three retries. Component type, filesystem device, and close-on-exec state are checked;
the retained root and leaf device/inode identities are checked separately. There is no
pathname-based recovery path.

These checks implement the cgroup-v2 no-processes-in-inner-nodes and single-writer
deployment assumptions narrowly: BPE requires an already empty, childless root under one
trusted manager. The implementation does not ask systemd to create a transient scope and
does not repair, migrate, or take ownership of an existing hierarchy.

## Empty-leaf lifecycle

The leaf name is internal: `bpe-q-` plus one fresh random 256-bit nonce. A collision fails
closed as `creation_conflict`; the probe does not select another name after observing
unexpected concurrent state. The leaf must remain the root's only child, an empty
unfrozen `domain`, with no processes, threads, subtree controllers, or child cgroups. Its
retained descriptor and root-visible entry must continue to name the same device and
inode.

The policy fixes the following cgroup control values. Every write is followed by exact ASCII
readback before cleanup, and the retained-leaf handoff repeats the same eight reads without
performing any writes:

| Control | Version-1 value |
|---|---|
| `memory.max` | `resource_profile.memory_bytes`, which must be 4096-byte aligned |
| `memory.swap.max` | `0` |
| `pids.max` | `resource_profile.pids_max` |
| `memory.oom.group` | `1` |
| `cpu.max` | `100000 100000` |
| `cpu.max.burst` | `0` |
| `cgroup.max.depth` | `0` |
| `cgroup.max.descendants` | `0` |

The `cpu.max` setting qualifies one-CPU-equivalent fair-class bandwidth at a 100 ms period;
it is not an exercise of the profile's CPU-time deadline and does not establish realtime
scheduling containment. Likewise, writing `memory.max`, zero swap, and `pids.max` to an
empty leaf proves control availability and exact readback, not behavior under pressure.
The profile's wall-clock, CPU-time, file-descriptor, file-size, stack, stdout, stderr,
tmpfs, network, and core-dump controls are not implemented by this probe.

## Cleanup boundary

Qualification first verifies that `cgroup.kill` can be opened for writing. Cleanup then
opens `cgroup.events`, writes `1` to `cgroup.kill` while the leaf is known to be empty,
requires `populated 0`, verifies leaf identity, removes the leaf with descriptor-relative
`rmdir`, and verifies that the random name is absent. A successful qualification must
finish its primary cleanup within a five-second monotonic budget, after which the delegated
root must again be empty and childless. Individual kernel syscalls are not preempted by
that userspace clock.

If normal cleanup fails before removal (including before `cgroup.events` can be opened),
the implementation makes one narrower fallback attempt. Because this phase never creates
a process, that fallback only compares the retained leaf descriptor with the exact
root-visible random name and asks the kernel to remove that empty leaf. It does not signal,
wait for, move, or inspect a process. An identity mismatch, populated or nonempty leaf,
failed removal, or unverifiable absence returns `cleanup_incomplete`; it never reports a
successful qualification with residual state. This best-effort failure cleanup may run
after the primary success budget has expired, but it can never convert the original failure
into a successful report. Failed rollback immediately after leaf creation uses the same
`cleanup_incomplete` classification if removal or descriptor closure cannot be completed.

No descendant is ever created, so the successful `cgroup.kill` write is only an
**empty-leaf write test**. It does not demonstrate signaling, reaping, or race-safe cleanup
of a live or forking process tree. In addition, successful `rmdir` and absence of the leaf
name do not prove that every kernel object associated with a dying cgroup has been
reclaimed. Accordingly the report fixes `dying_descendants_reclaimed: false`.

`LinuxCgroupV2RetainedLeaf.cleanup()` is the live-leaf variant used by the fixed-fixture
supervisor.
It permits prior population, writes `cgroup.kill`, waits within the same fixed monotonic
budget for `populated 0`, identity-checks and removes only the original random leaf, and
re-audits the delegated root. `cleanup_with_timeout_ms(...)` performs the same operation
with an exact positive integer timeout no greater than the policy's fixed cleanup bound, so
an orchestrator can consume only the time remaining in a larger shared deadline. Invalid
timeout input leaves the handle active. Both entry points share one terminal, thread-safe,
idempotent outcome: repeated calls return the first duration or re-raise the exact first
failure. Context-manager cleanup preserves an active body exception and annotates it when
cleanup also fails. `cleanup_completed` and `cleanup_error` expose that terminal outcome.
This cleanup does not reap processes itself; pidfd observation and reaping remain the
launcher's and orchestrator's responsibility.

## Report and nonclaims

The report identity binds the entire canonical report body, including the fresh nonce,
policy and resource-profile identifiers and digests, audience and delegated-root labels,
observed values, cleanup evidence, and every explicit nonclaim:

```text
SHA256(
    b"BPE\x00cgroup-v2-qualification\x00v1\x00"
    || canonical_json_bytes(report excluding qualification_id)
)
```

It records the admitted root/controller observations, configured values, exact readback,
empty-leaf kill write, population checks, identity check, name removal, and cleanup
duration. It is created only after cleanup and final root revalidation.

The schema permanently fixes all of the following to `false`:

- `process_creation_probed`, `clone3_qualified`, `pidfd_qualified`, and `process_created`;
- `execution_started`, `candidate_bytes_accessed`, and `limits_exercised`;
- wall-time, CPU-time, output, filesystem, and network enforcement;
- complete resource-profile enforcement and dying-descendant reclamation; and
- `execution_authorized` and `authoritative`.

The report is neither signed nor connected to a dispatch claim, ingress receipt, or claim
ledger. A stale or replayed report cannot authorize launch. Because the delegated root can
change immediately after the final check, a later supervisor must perform its own
fail-closed, launch-time validation.

## Bounded failures

Failures derive from `LinuxCgroupError` and expose a bounded `reason` rather than caller
paths or raw kernel details:

| Area | Reasons |
|---|---|
| Host ABI | `unsupported_platform`, `unsupported_architecture`, `unsupported_page_size`, `openat2_unavailable`, `openat2_abi_incompatible` |
| Inputs and delegation | `invalid_inputs`, `unsafe_delegate`, `not_cgroup_v2`, `delegation_unverified`, `delegate_busy`, `controllers_unavailable`, `controller_state_mismatch` |
| Leaf lifecycle | `creation_conflict`, `configuration_rejected`, `readback_mismatch`, `cgroup_changed`, `cleanup_timeout`, `cleanup_incomplete`, `resource_exhausted`, `io_failure` |

`LinuxCgroupUnavailable`, `LinuxCgroupRejected`, and `LinuxCgroupLifecycleError` provide
coarser categories. A failure never selects a weaker implementation and never grants
execution permission.

## Native verification boundary

After ordinary CI succeeds for a same-repository `main` push, the separate trusted
`workflow_run` job runs the rebuilt installed wheel as PID 1 inside a disposable privileged,
private cgroup namespace. The probe creates separate manager and empty delegate cgroups,
enables the exact controllers, and first exercises the complete empty-leaf lifecycle on
native x86-64 cgroup v2. It asserts that the leaf is gone and verifies the report's
nonexecution claims.

The same dedicated probe then provisions private claim and launch ledgers, creates and
claims one short-lived signed intent for the reviewed launcher digest, and calls the
production fixed-fixture orchestrator against the same still-empty delegation. It requires
one successful canonical replay, exactly one durable claim and attempt, exact receipt
recovery, unchanged caller-owned descriptors, and no remaining child cgroup. This second
operation does create the trusted launcher and built-in no-exec fixture; it does not change
the earlier empty-leaf report's fixed nonexecution fields or make the orchestration result
authoritative.

The container has no systemd manager, so the test installs the exact `user.delegate=1`
kernel xattr itself. This verifies the kernel-facing marker and cgroup lifecycle, not
production systemd provenance; deployment must still provision the delegation with systemd,
provide outer controller-death containment, and satisfy every admission check independently.

## Trust assumptions and next boundary

Phase 1B.1 assumes a trusted Linux kernel and supervisor, a correctly provisioned unified
cgroup-v2 hierarchy, an exclusive systemd delegation, and no hostile same-UID or
ptrace-capable process. Root, a compromised kernel or supervisor, descriptor injection,
and concurrent mutation by a process with equivalent authority are outside the boundary.
It provides no mount-namespace, filesystem, network, executable, environment, output, or
candidate isolation.

The Phase 1B.2b-1 blocking privileged native gate is configured to exercise a fixed inert
fixture and launcher that atomically creates the child in a leaf with
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)`. When it passes on native x86-64, it qualifies
pidfd stop/exit observation and reaping, one live `cgroup.kill`, `populated 0`, and exact
cleanup. Gate code and configuration alone are not qualification evidence. The atomic
Python boundary is now implemented: it performs authorization, artifact, and host
preflight before durable launch-attempt consumption, verifies that committed receipt, and
only then acquires this fully revalidated retained handle. It duplicates the leaf into fixed
launcher descriptor `4` and passes the remaining shared cleanup allowance to
`cleanup_with_timeout_ms(...)`; cgroup cleanup and adopted-child reaping cannot each reset
the signed total deadline. If no allowance remains, a one-millisecond safety cleanup may
still run, but the orchestration result records the deadline overrun. A recovered ambiguous
receipt never reaches this API.

The orchestrator's success or launcher-failure result requires cgroup cleanup to complete,
but that result is unsigned and nonauthoritative. Abrupt controller death is not covered:
there is no `PDEATHSIG`, so deployment needs an outer systemd unit or PID namespace that
independently owns process and cgroup cleanup. Real resource pressure and a forking
descendant require later fixed fixture protocols. No phase may infer those claims from
empty-leaf or single-child success, and this boundary still exposes no caller-controlled
argv, environment, executable path, external fixture, job, or candidate bytes. See [atomic
fixed-fixture orchestration](inert-fixture-orchestration.md).

Primary references are the kernel's [cgroup v2
documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html), systemd's
[cgroup delegation model](https://systemd.io/CGROUP_DELEGATION/), and the Linux
[`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html),
[`clone3(2)`](https://man7.org/linux/man-pages/man2/clone.2.html),
[`pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and
[`pidfd_send_signal(2)`](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)
manual pages.
