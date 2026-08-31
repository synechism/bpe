# Prepared evaluation jobs

Version 1 freezes the complete input to a future evaluator without granting permission to
run it. A prepared job is a canonical manifest plus an exact content-addressed blob set;
it is useful for deterministic construction, transfer, inspection, and integrity checks.
There is no candidate execution or Firecracker integration in this milestone.

## Non-executable contract

Every manifest fixes `status: "prepared"`, `execution_authorized: false`, and
`authoritative: false`. The schema exposes no host path, argv, environment-variable map,
archive entry, executable worker request, or dispatch method. Changing that boundary
requires a new protocol and security review; a consumer must never infer authority from
the presence of a valid bundle.

The manifest embeds and hashes the exact evaluation request, suite, experiment,
environment, reward policy, pathname-free task plan, and scoring contract. Validation
cross-binds their task/version/bundle, suite, experiment, model/checkpoint/seed/sample,
environment, policy, harness, and expected-grader identities. The contract must be exactly
derived from the plan, the task must appear exactly once in the suite, and the candidate
and every functional input must have one exact physical blob identity.

Version 1 is intentionally narrow: one XDP program, the `bpf_prog_run/xdp@1` functional
profile, post-extraction plain bounded `text/x-c` candidate bytes, and content-addressed
functional inputs. The suite freezes the evaluation-plan digest as well as the scoring
contract digest, so changing an assertion, semantic obligation, program field, public SDK,
or timeout changes the precommitted suite identity.
Neither a private task pathname nor its original input pathname survives preparation.

## Closed bundle format

```text
job/
├── manifest.json
└── blobs/
    └── sha256/
        └── <lowercase SHA-256 digest>
```

The tree must contain exactly those entries and exactly the blobs named by the manifest.
The manifest is strict canonical JSON: duplicate keys, non-finite numbers, lone Unicode
surrogates, unknown fields, noncanonical encodings, and excessive depth or node count are
rejected. Resource limits are fixed:

| Resource | Version 1 limit |
|---|---:|
| Manifest | 256 KiB |
| Blob count | 256 |
| One blob | 16 MiB |
| All blobs | 128 MiB |

`write_evaluation_job_bundle` stages a new tree, verifies every supplied immutable byte
against its declared size and digest, loads it through the production reader, and only
then publishes it. It refuses to replace an existing target and requires a caller-owned
parent directory with no group or other write permission. It retains that parent directory
descriptor and performs staging, writes, target reservation, publication, and verification
relative to pinned descriptors; it also fails if the caller-visible parent path changes.
The manifest is moved last, so an interrupted publication can leave an incomplete
reservation but never a bundle that passes verification.

`load_evaluation_job_bundle` opens the root and descendants relative to pinned directory
descriptors. It rejects symlinks, cross-device components, non-regular blobs, external hard
links, inode changes during open, metadata changes during a bounded read, and any extra or
missing tree entry. It verifies every blob once into memory, checks the candidate as strict
plain C source, re-enumerates the pinned directories, and returns immutable bytes. A
consumer uses those returned bytes rather than reopening a pathname.

This portable `openat`-style loader materially narrows filesystem races, but is not the
Linux worker boundary. Phase 1B.0 now injects a stricter loader opener that resolves every
source component with `openat2` restrictions, requires the manifest digest from an exact
committed dispatch claim, and copies the sealed bytes into a private worker-owned tree.
That ingress remains non-executing and nonauthoritative; see
[Linux claimed-job ingress](linux-ingress.md).

Phase 1B.1's [cgroup-v2 empty-leaf qualification](cgroup-qualification.md) is also separate
from the job format. It never reads a manifest or candidate blob, and its unsigned report
does not bind a prepared job, ingress receipt, or dispatch claim. A qualified empty leaf
therefore cannot make this permanently non-executable v1 manifest executable.

## Trust and anchoring

The manifest digest covers all embedded identities and the exact blob table. Passing that
digest to the loader as `expected_manifest_sha256` establishes that the bytes match the
caller's chosen value; omitting it produces an explicitly unanchored diagnostic load.

The digest must come from outside the bundle. A self-consistent manifest and blob tree can
always be replaced together, so **every future dispatch must require an externally obtained
manifest digest plus authenticated evaluator context**. Even an anchored prepared bundle
remains `authoritative: false`: authority requires an implemented microVM worker and its
authenticated result attestation.

Phase 1A supplies the first separate authenticated context: a short-lived Ed25519
authorization binding the job-manifest digest and typed execution profile, followed by an
atomic one-shot claim. It intentionally does not modify job v1 and still cannot start
execution. See [signed dispatch admission](dispatch-admission.md).

The job manifest's `restore_nonce` distinguishes independently prepared jobs and repeated
qualification attempts. It is not sufficient as a live-instance nonce when the same job is
retried. Phase 1A's independently unique `dispatch_nonce` is the per-authorization instance
nonce; a future executor must bind each Firecracker CID, socket, and restore session to it.

## Firecracker execution constraints

The future worker design treats snapshot restore as a fresh-machine operation:

- create a fresh Firecracker process for each snapshot load and keep the guest paused until
  external artifacts, the job anchor, and instance identity are checked;
- treat snapshots as trusted evaluator artifacts, not as safe untrusted input;
- pin the memory snapshot together with external disk, vsock, and TAP configuration;
- enforce Firecracker, host architecture, CPU vendor/model, and CPU-feature compatibility;
- allocate a unique restore nonce, guest CID, and host vsock path per instance;
- establish a new vsock session after restore and implement application framing, partial
  I/O handling, byte limits, and host-monotonic deadlines; and
- destroy the instance and its writable layer after one job.

These are design requirements, not claims about current worker behavior. Primary sources
are Firecracker's [snapshot support](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md),
[snapshot versioning](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/versioning.md),
[vsock guide](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/vsock.md),
[v1.16.1 API schema](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/firecracker/swagger/firecracker.yaml),
and Linux [`vsock(7)`](https://man7.org/linux/man-pages/man7/vsock.7.html).
