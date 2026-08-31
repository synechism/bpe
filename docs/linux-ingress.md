# Linux claimed-job ingress

Phase 1B.0 implements one narrow operation: copy the exact prepared job named by an
already committed dispatch claim from a trusted spool descriptor into a private worker
store. The operation is Linux x86-64 only, accepts no caller-selected pathname, and has no
portable fallback. It does not compile, load, or execute eBPF and cannot produce an
authoritative grading result.

The public contracts are `LinuxJobIngressPolicy`, `LinuxJobIngressReceipt`,
`SealedJobIngress`, and `ingress_claimed_evaluation_job(...)` in `bpe.ingress`. Their
published JSON schemas are
[`linux-job-ingress-policy-v1.json`](../schemas/linux-job-ingress-policy-v1.json) and
[`linux-job-ingress-receipt-v1.json`](../schemas/linux-job-ingress-receipt-v1.json).

## Public boundary

```python
def ingress_claimed_evaluation_job(
    claim: DispatchAdmissionReceipt,
    policy: LinuxJobIngressPolicy,
    *,
    ledger: DispatchClaimLedger,
    source_spool_fd: int,
    worker_store_fd: int,
) -> SealedJobIngress: ...
```

The two root arguments are pre-opened directory file descriptors, not paths. The trusted
worker supervisor is responsible for opening the intended directories and for mapping the
policy's `source_root_id` and `worker_root_id` labels to those descriptors. Version 1 does
not derive or authenticate that mapping from kernel metadata.

Ingress duplicates both descriptors with `F_DUPFD_CLOEXEC` and operates only relative to
the duplicates. An accepted root must be a readable directory descriptor rather than an
`O_PATH` descriptor. The source root must be owned by root or the effective worker UID and
must not be group- or other-writable. The worker root must be owned by the effective worker
UID with mode exactly `0700`. Source and worker roots cannot be the same directory.
Ingress also walks pinned directory ancestry in both directions and rejects either root as
an ancestor of the other in the current mount topology. Every selected source directory is
additionally rejected when its device/inode identity equals the worker root, which catches
a bind-mount alias of the digest namespace or selected job tree. The trusted supervisor
must not map the worker root to a bind alias of any other source-spool descendant.

On success, the result contains:

- `receipt`: the typed ingress receipt;
- `job`: a `LoadedEvaluationJob` made from the verified worker-owned copy; and
- one retained descriptor for the published worker-object directory.

`SealedJobIngress.fileno()` exposes that retained descriptor without reopening a path.
Callers must close the result, directly or as a context manager. Closing invalidates only
the retained descriptor; the returned immutable in-memory job and the published object are
not deleted.

## Signed policy and claim-ledger coupling

The ingress policy is authenticated transitively by signed dispatch admission. It is not
a second independently signed envelope. For version 1, the dispatch authorization's
`policy_id` is the ingress policy's `policy_id`, and its `policy_sha256` is the canonical
JSON SHA-256 of the exact `LinuxJobIngressPolicy`. There is no wrapper-policy digest in
this contract.

Ingress performs the following checks before reading the spool:

1. It strictly revalidates the claim and policy models.
2. It recomputes the canonical policy digest and requires exact agreement on policy ID,
   policy digest, and worker-pool audience with the dispatch claim.
3. It requires a concrete `DispatchClaimLedger` and calls its read-only
   `verify_committed_receipt(...)` method. That method strictly revalidates and hashes the
   claim receipt, then requires the exact receipt and recomputed dispatch binding to match
   the current version-1 ledger row. Ingress neither advances the ledger clock nor writes
   another consumption record.

The ledger proof matters because a structurally valid receipt object alone is not evidence
that the one-shot authorization was durably consumed. Conversely, a committed claim does
not authorize an arbitrary ingress policy: the signed authorization already fixed its
canonical policy digest.

The deterministic worker-object ID cross-binds all three identities:

```text
SHA256(
    b"BPE\x00linux-job-ingress-object\x00v1\x00"
    || raw_sha256(dispatch_claim_receipt)
    || raw_sha256(job_manifest)
    || raw_sha256(ingress_policy)
)
```

A retry, a different policy, or a different prepared job therefore selects a different
worker object.

## Policy contract

Only the following version-1 policy is accepted. Fields shown as literals cannot be
relaxed by the caller.

| Field | Version-1 value or meaning |
|---|---|
| `schema_version` | `bpe.linux-job-ingress-policy.v1` |
| `policy_id` | Signed stable identity for this policy |
| `worker_pool_audience` | Must equal the signed dispatch audience |
| `source_root_id` | Trusted deployment label for `source_spool_fd` |
| `worker_root_id` | Trusted deployment label for `worker_store_fd` |
| `host_platform` / `host_architecture` | `linux` / `x86_64` |
| `source_layout` | `sha256-job-directory-v1` |
| `source_open_method` | `openat2-v1` |
| `regular_file_open_method` | `openat2-opath-procfd-reopen-v1` |
| `trusted_procfs_required` | `true` |
| `resolve_beneath` | `true` |
| `resolve_no_xdev` | `true` |
| `resolve_no_symlinks` | `true` |
| `resolve_no_magiclinks` | `true` |
| `openat2_eagain_retries` | `3` |
| `max_manifest_bytes` | 262,144 bytes |
| `max_blobs` | 256 |
| `max_blob_bytes` | 16,777,216 bytes |
| `max_total_blob_bytes` | 134,217,728 bytes |
| `copy_method` | `verified-bounded-byte-copy-v1` |
| `publish_method` | `renameat2-noreplace-v1` |
| `worker_directory_mode` / `worker_file_mode` | `0700` / `0600` |
| `execution_permitted` | `false` |
| `authoritative_ready` | `false` |

The runtime also checks the 64-bit x86-64 ABI, pinned syscall numbers, `open_how` layout,
required descriptor flags, and `F_DUPFD_CLOEXEC`. Unsupported hosts fail before the ledger
or supplied descriptors are inspected.

## Digest-addressed source and strict opening

The source descriptor names a spool containing a digest namespace. It may contain many
jobs, but the selected job must have this exact closed inner layout:

```text
<source_spool_fd>/
└── sha256/
    └── <job_manifest_sha256>/
        ├── manifest.json
        └── blobs/
            └── sha256/
                └── <blob_sha256>
```

The manifest digest comes from the committed claim, never from a path supplied alongside
the call. Every untrusted source component is opened with `openat2(2)` using all of
`RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`, `RESOLVE_NO_SYMLINKS`, and
`RESOLVE_NO_MAGICLINKS`. Open flags include `O_PATH | O_NOFOLLOW | O_CLOEXEC`, plus
`O_DIRECTORY` for directories. There are at most three retries after `EINTR` or `EAGAIN`;
exhaustion fails closed. There is no `openat(2)` fallback for source resolution.

An `O_PATH` descriptor cannot supply file bytes. To preserve the resolution result, the
implementation opens and verifies `/proc/self/fd` as procfs, reopens the numeric `O_PATH`
descriptor entry relative to that trusted procfs directory, and compares device and inode
before accepting the readable descriptor. Type and same-device checks are repeated;
regular files must also have link count one. The procfs reopen uses
`O_RDONLY | O_NONBLOCK | O_CLOEXEC` so a raced special file cannot turn the verification
read into a blocking operation. The source-side `RESOLVE_NO_MAGICLINKS` rule applies to the
untrusted spool; the deliberate procfs descriptor reopen is a separate trusted operation.

The prepared-job loader then enforces the exact closed tree and fixed resource ceilings.
It requires canonical manifest bytes matching the claim's manifest digest, verifies every
blob's declared size and SHA-256, checks file metadata before and after each bounded read,
re-enumerates directories after loading, and validates the candidate as bounded plain C
source. The accepted manifest and blobs are retained as immutable Python bytes. Later
copying never reopens a source pathname.

## Verified copy and no-replacement publication

The worker object is published as:

```text
<worker_store_fd>/
└── <worker_object_id>/
    ├── manifest.json
    └── blobs/
        └── sha256/
            └── <blob_sha256>
```

Ingress creates a random `0700` staging directory under the pinned worker root. It writes
only the already verified in-memory bytes, using exclusive temporary `0600` files, bounded
writes, per-file `fsync`, and descriptor-relative rename. It then synchronizes the blob,
directory, and staging descriptors and reloads the entire staged tree. The staged root and
directories must be worker-owned mode `0700`; every file must be worker-owned mode `0600`,
same-device, regular, and single-linked. Its anchored manifest, metadata, and immutable
bytes must exactly equal the sealed source view.

Publication is one `renameat2(2)` call relative to the worker-root descriptor with
`RENAME_NOREPLACE`. The implementation never removes or overwrites an existing target. On
a new publication it synchronizes the worker-root directory, reloads through the retained
staging descriptor, and verifies the published tree again before returning.

The deterministic name makes retries idempotent without weakening no-replacement
semantics. If the target already exists, ingress opens it relative to the trusted worker
root and accepts it only if its closed tree, ownership, modes, anchor, and immutable bytes
exactly match the newly sealed source. Any mismatch is `destination_conflict`. An accepted
existing object is returned through its own retained descriptor; it is not rewritten.

The implementation performs the file and directory `fsync` sequence needed by this
contract and best-effort cleanup of an unpublished staging tree on ordinary failures.
However, Phase 1B.0 has not yet completed filesystem-specific fault injection or real
power-cut durability qualification. A process or host crash can also leave an abandoned
hidden staging directory that requires trusted operational cleanup. The function returns
the receipt in memory; it does not independently persist or sign that receipt.

## Receipt contract

`LinuxJobIngressReceipt` records exactly what this copy operation established:

- `schema_version: "bpe.linux-job-ingress-receipt.v1"` and
  `status: "ingressed_not_executed"`;
- the deterministic `worker_object_id` and canonical
  `dispatch_claim_receipt_sha256`;
- authorization ID and digest, claim ID and nonce, dispatch nonce, and anchored job
  manifest digest;
- ingress policy ID and digest, worker-pool audience, and the source/worker root labels;
- the fixed source-open, regular-file-open, resolution, copy, and publication methods;
- verified manifest size, blob count, and total blob bytes; and
- `source_verified: true`, `worker_copy_verified: true`, and
  `published_without_replacement: true`.

The model validator recomputes the worker-object ID from the claim-receipt, job-manifest,
and policy digests. The receipt always fixes `execution_started: false` and
`authoritative: false`. It is deterministic local evidence, not a signed result
attestation, replay proof, or grading artifact.

## Bounded failures

Ingress failures derive from `LinuxIngressError` and expose a bounded `reason` value.
Callers should branch on that value rather than parsing an `OSError`, chained exception, or
human-readable message. The public messages do not echo caller paths or source component
names.

| Area | Reasons |
|---|---|
| Host contract | `unsupported_platform`, `unsupported_architecture`, `openat2_unavailable`, `openat2_abi_incompatible`, `renameat2_unavailable`, `trusted_procfs_unavailable` |
| Claim and policy | `invalid_claim`, `uncommitted_claim`, `policy_mismatch` |
| Source | `unsafe_source_root`, `unsafe_source_resolution`, `source_missing`, `source_unreadable`, `source_changed`, `invalid_bundle` |
| Worker store | `unsafe_destination`, `destination_conflict`, `resource_exhausted`, `io_failure` |

`LinuxIngressUnavailable`, `LinuxIngressRejected`, and `LinuxIngressStorageError` provide
coarser categories for unavailable kernel facilities, rejected inputs/state, and worker
storage failures. No failure authorizes execution or permits a weaker fallback.

## Threat assumptions and limitations

Phase 1B.0 narrows pathname races and copy ambiguity; it is not a hostile-host security
boundary. Its guarantees depend on all of the following assumptions:

- A trusted supervisor supplies the correct pre-opened source and worker root descriptors
  for the policy's root IDs. The root IDs are authenticated labels, not proofs of mount,
  device, inode, or pathname identity. In particular, the supervisor must not supply an
  unselected source-spool descendant through a separate bind-mount alias as the worker
  root; version 1 does not enumerate the entire spool to discover that configuration.
- `/proc/self/fd` is a trusted, genuine procfs view in a trusted mount namespace, and the
  local kernel implements the pinned x86-64 syscall and descriptor semantics.
- The source and worker roots are on trusted local filesystems with ordinary Linux
  inode, hard-link, `renameat2`, and `fsync` behavior. Network, FUSE, overlay edge cases,
  and deliberately hostile filesystems are outside this contract.
- The worker runs under a dedicated UID. Untrusted candidate code and other adversarial
  processes do not share that UID, its file descriptors, or write access to its roots.
  A malicious same-UID process is outside scope.
- The dispatch issuer, trust-store distribution, claim-ledger storage, ingress policy, and
  supervisor configuration are trusted control-plane inputs.

Root, a compromised kernel, ptrace-capable host processes, a compromised supervisor, and
hostile storage can violate these assumptions and are outside scope. Retaining the worker
object descriptor pins the opened directory inode; it does not make the directory immune
to mutation by root or another process with sufficient access. The immutable `job` bytes
remain the handoff boundary for later code.

The current `fsync` sequence is intentional but is not yet a qualified claim of survival
across real power loss, controller reordering, or every supported local filesystem.

Phase 1B.1's [cgroup-v2 empty-leaf qualification](cgroup-qualification.md) is an
independent host diagnostic. It does not accept an ingress receipt, inspect the retained
worker-object descriptor, or extend the signed policy/claim binding. Conversely, a
successful ingress receipt does not select a delegated cgroup root or authorize the
qualification report to launch anything. A later execution entry point must bind these
separate prerequisites under a newly reviewed authorization contract.

## Remaining work

Ingress is still non-executing infrastructure. Before any authoritative evaluation, the
project still needs:

- production provisioning and audit of the root-ID-to-descriptor mapping, dedicated UID,
  mount namespace, trusted procfs, supported local filesystems, and abandoned-stage
  recovery;
- native Linux adversarial and power-cut/fault-injection qualification of publication and
  recovery, plus an explicit supported-filesystem matrix;
- production provisioning of the implemented nonauthorizing cgroup-v2 empty-leaf probe,
  followed by a Phase 1B.2 native `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` supervisor
  tested with a fixed inert fixture, monotonic deadlines, output ceilings, live limits,
  pidfd lifecycle handling, and race-safe descendant cleanup;
- pinned compilation and ELF/BTF/object-policy inspection;
- the libbpf verifier/test-run harness and canonical trace capture;
- fresh-process Firecracker restore, isolated writable state, unique instance identity,
  and bounded authenticated guest transport; and
- signed result attestation, replay verification, deterministic rescoring, and an
  official-result eligibility audit.

Supporting another architecture, a different policy wrapper, a procfs-free exact-inode
reopen strategy, or a different publication/filesystem contract requires a new version
and security review. Version 1 must fail closed instead of silently substituting any of
those mechanisms.
