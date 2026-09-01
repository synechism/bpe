# Environment contract

The planned evaluator has two security boundaries and a strict public/private split. Phase
0 implements separate projections, leakage linting, a bounded capability-only subprocess
protocol, and non-executable prepared job bundles. Phase 1A adds signed one-shot dispatch
admission. Phase 1B.0 adds Linux-only verified ingress into a private worker tree, and
Phase 1B.1 adds an empty-leaf cgroup-v2 qualification probe. Phase 1B.2a adds a pure-Python
signed intent claim for one future fixed inert fixture, and Phase 1B.2b-0 adds a separate
pure-Python atomic launch-attempt consumption ledger. Phase 1B.2b-1 adds process-free
immutable artifact preflight plus a configured blocking privileged native x86-64
live-kernel qualification probe for the fixed launcher. Only a successful run of that gate
on a native x86-64 CI host produces lifecycle-qualification evidence. None of the production
Python boundaries is yet a process
launcher; atomic launch orchestration and candidate isolation remain later Phase 1 work.

## Agent-visible environment

The model receives the prompt, broken source or generation specification, a read-only
public SDK, fixed candidate-output contract, and black-box diagnostics from its own prior
attempt. It does not receive the reference source, mutation label, hidden inputs,
semantic obligations, negative controls, grader binaries, or sealed corpus.

Useful affordances are intentional. A senior systems engineer with exactly the same tools
should be able to make sustained progress and eventually reach a perfect score. Removing
Clang, headers, diagnostics, or development examples would change the capability being
measured into "working around a broken environment."

Public development programs and oracle inputs are disjoint from calibration, validation,
and sealed evaluation at the repository/program-family level. The reference implementation
lives behind a narrow service/worker interface rather than inside the candidate's filesystem.

## Compiler sandbox

Candidate text first enters an unprivileged, networkless compiler sandbox with a minimal
read-only filesystem. The candidate cannot control flags, target, environment variables,
headers, output paths, section/program type policy, or loader behavior.

The planned fixed recipe pins target endianness, target architecture, `-mcpu`, Clang build,
public headers, `SOURCE_DATE_EPOCH`, path remapping, CPU/memory/PID/output limits, and the
dependency closure. Dependencies outside the public SDK fail object policy.

## Verifier microVM

The host kernel never processes candidate BPF. A disposable Firecracker guest owns:

- one vCPU;
- pinned kernel image, config, and BTF;
- read-only rootfs plus tmpfs;
- no network or persistent bpffs;
- a narrow vsock protocol;
- root inside the guest; and
- a hard hypervisor deadline.

The Phase 1 design loads each snapshot into a fresh Firecracker process, leaves the guest
paused until its external artifacts and job identity have been checked, and destroys the
instance after one candidate. Boot/vsock/sentinel failure is `INFRA_ERROR` and retryable;
a candidate verifier/execution deadline is a scored timeout. Guest console and dmesg are
scanned and retained for warnings, oopses, and panics.

Snapshots are trusted evaluator artifacts, not an untrusted serialization format. The
memory snapshot is only one part of the machine: disk images, vsock, and TAP devices remain
external resources and must be independently pinned and isolated. Restore also requires a
compatible Firecracker version, host architecture, CPU vendor/model, and CPU feature set.
The environment identity therefore binds each snapshot component as well as the runtime
and host/CPU compatibility profile.

A restored vsock device does not preserve a usable application session. The host opens a
new connection for every restored guest and the application protocol handles framing,
partial reads and writes, message limits, and host-monotonic deadlines. One unique guest
CID and host Unix-socket path are allocated per live instance. No current BPE code starts
Firecracker, restores a snapshot, opens vsock, or executes a candidate.

Native Linux execution is a development convenience only. It is never official and must
print that distinction. Synthetic evidence is likewise nonofficial. macOS can validate
tasks, score evidence, verify replay integrity, and test orchestration, but it can never
claim a verifier result. The Phase 0 worker only probes host prerequisites; it does not yet
compile or load candidate programs, even when Clang, bpftool, and BTF are present.

The development subprocess accepts one strict LF-terminated request and then exits. It
binds each response to the request ID and canonical request digest, but it is not an
authenticated channel and supplies no execution method. The future microVM boundary uses a
separately versioned bounded vsock protocol; a subprocess response cannot be relabeled as a
microVM attestation. See [the worker protocol](worker-protocol.md).

## Prepared job boundary

A version 1 prepared job freezes canonical copies of the request, suite, experiment,
environment, reward policy, grader identity, pathname-free task plan, exact scoring
contract, candidate, and hidden functional inputs. Every identity is cross-checked and the
payload bytes live in an exact content-addressed blob set. The manifest permanently says
`execution_authorized: false` and `authoritative: false`; it contains no host filesystem
path, argv, environment-variable map, archive entry, or dispatch method.

Preparation and verification do not cross the microVM boundary. The loader returns sealed
in-memory bytes, but any future dispatcher must additionally require the manifest digest
from an external authenticated trust anchor. See [prepared evaluation jobs](evaluation-jobs.md).

## Dispatch-admission boundary

`bpe.signed-dispatch-authorization.v1` is a separate short-lived Ed25519 envelope. It binds
the prepared job and request, experiment/environment, typed execution/resource profiles,
worker-pool audience, purpose, policy ID and digest, and retry lineage through the exact
parent-claim receipt digest. Verification uses an out-of-band trusted public-key store.
Admission records a worker-generated claim nonce, rejects clock rollback with a durable
high-water mark, and consumes the authorization ID, envelope digest, dispatch nonce, claim
ID, and retry parent in one durable SQLite transaction so concurrent reuse has one winner.

Dispatch admission does not itself cross the artifact-ingress or execution boundary. Its
receipt fixes `execution_started: false` and `authoritative: false`; execution profile v1
likewise fixes `execution_implemented: false` and `authoritative_ready: false`. Phase 1B.0
now closes only the Linux spool-to-worker copy boundary: it proves the exact committed
receipt, binds the signed ingress policy, uses fail-closed `openat2` resolution, and
publishes a verified private copy with `renameat2(RENAME_NOREPLACE)`. It still launches
nothing and remains nonauthoritative. See [signed dispatch admission](dispatch-admission.md)
and [Linux claimed-job ingress](linux-ingress.md).

## Cgroup qualification boundary

Phase 1B.1 qualifies only a point-in-time empty-leaf lifecycle beneath a trusted,
pre-opened, current-UID-owned systemd delegation. It checks cgroup-v2 filesystem identity,
the `user.delegate=1` marker, an empty childless domain root, and exact `cpu`, `memory`, and
`pids` delegation state. The marker is not sufficient on its own. The function creates one
random leaf, writes and exactly reads back page-aligned memory, zero-swap, PID, OOM-group,
fair-class CPU-bandwidth, zero-burst, and zero depth/descendant settings, writes
`cgroup.kill` while the leaf is empty, observes `populated 0`, and removes the leaf.

The returned report is unsigned, nonauthorizing, and created only after that leaf no
longer has a name. No process, candidate byte, compiler, `clone3`, or pidfd participates;
no resource limit is exercised. The probe supplies no filesystem or network isolation and
does not show that dying descendants can be reclaimed. Successful `rmdir` also does not
prove kernel reclamation of the removed cgroup object. See [cgroup-v2 empty-leaf
qualification](cgroup-qualification.md).

## Inert-fixture intent-admission boundary

Phase 1B.2a authenticates short-lived Ed25519 metadata for one spawned, one-shot launcher
artifact, its seccomp policy, fixed launcher and built-in no-exec fixture protocols, typed
resources, deadlines, audience, and delegated-root label. It consumes each intent once in
one explicitly provisioned durable ledger bound to a worker-instance ID, claim-ledger ID,
and anchored absolute database path. The current API accepts no root descriptor, launcher
or executable path, argv, environment, job, candidate bytes, external fixture,
dispatch/ingress receipt, or Phase 1B.1 report, and it does not inspect the host or access
the named artifacts.

The resulting `claimed_not_started` receipt is exact committed prelaunch evidence. It fixes
launch authorization, process creation, execution, candidate/job access, and authority to
`false` and explicitly requires a separate launch ledger. Phase 1B.2b-0 now supplies that
process-free ledger: before any native boundary, it revalidates the original signed intent,
complete policy preimage, configured worker and ledger identities, exact committed claim,
claim timestamp, worker clock, and expiry, then atomically consumes the sole attempt. Its
`launch_attempt_consumed_not_started` receipt also fixes launch authorization, process
creation, execution, candidate/job access, retry permission, and authority to `false`;
neither receipt is launch authority. A terminal result requires another signing domain,
attestor trust role, and durable result/finalization ledger. See [inert-fixture intent
admission](inert-fixture-admission.md).

This claim is one-shot only within that configured physical database. Deployment must keep
one durable, non-clonable ledger ownership domain per worker and supply external uniqueness
and anti-rollback; local SQLite identity fields cannot prevent whole-file copies or rollback.

Phase 1B.2b-1 now authenticates and immutably seals the configured launcher artifact without
creating a process, while a separate blocking privileged Linux probe is configured to
exercise a fixed inert fixture created atomically with
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)`. When it passes on native x86-64, that narrow gate
qualifies pidfd lifecycle handling, one live `cgroup.kill`, reaping, and `populated 0`. Its
evaluator-only inherited seccomp case denies both normal and emergency
`pidfd_send_signal`; only the successful native `EPERM`/mask-`0x1c3` case qualifies the
emergency cleanup outcome under the fixed-child, trusted-kernel, single-writer assumptions;
the transcript does not independently prove the return from the emergency `cgroup.kill`
write. The gate's [native qualification report](native-launcher-qualification.md) preserves
raw replay inputs and cleanup observations but remains unsigned, freshness-unauthenticated,
non-durable, and nonauthoritative. Atomic Python orchestration remains
pending. Bounded signed
output/deadlines, real resource pressure, and forking-descendant cleanup remain later fixed
fixtures. Snapshot freshness, candidate execution, executable/argv/environment/dynamic-
loader qualification, and authoritative result attestations remain separate later
requirements.

For execution-profile v1, `snapshot_sha256` is the canonical JSON digest of the complete
typed `SnapshotComponents` record. It is not a direct digest of only `vm_state`, memory, or
the root filesystem. The profile also requires the environment's resource-limit digest to
equal its typed resource profile and fixes one vCPU with SMT disabled.

## Environment identity

Version strings are not enough. Every run records content digests for the kernel image,
config, BTF, rootfs, snapshot, Clang binary and compile recipe, libbpf runner, resource
limits, task pack, public SDK, normalizer version and digest, and harness commit. `grader_id`
binds those inputs.

Different grader identities never share a leaderboard column. A replay under a new reward
policy is allowed because reward uses stored stage evidence; a policy needing new evidence
requires re-execution.

Environment provenance still does not authenticate a result. A future authoritative
measurement needs both the pinned microVM identity and the replay manifest digest recorded
by an independently authenticated evaluator. Phase 0 has neither real candidate execution
nor issuer authentication, so its report schema forbids `official: true` even when a replay
matches a supplied anchor registry. Native, synthetic, and unanchored runs remain useful
diagnostics with weaker provenance.

Firecracker behavior and compatibility constraints are grounded in its primary
documentation: [snapshot support](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md),
[snapshot versioning](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/versioning.md),
[vsock](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/vsock.md), and
the [v1.16.1 API schema](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml).
