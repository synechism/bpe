# Signed dispatch admission

Phase 1A introduces a control-plane admission primitive before BPE introduces any
candidate execution. A prepared evaluation job is still permanently non-executable by
itself. The only object that can authorize a future dispatch is a short-lived Ed25519
authorization issued outside the worker and consumed exactly once in a durable claim
ledger.

This milestone does **not** launch Clang, Firecracker, or a guest agent. A successful
admission receipt fixes `execution_started: false` and `authoritative: false`.

## Bound authority

The signed payload commits to all inputs that may affect whether a job is eligible for
dispatch:

- the exact prepared-job manifest, request, experiment, and environment digests;
- the typed execution-profile and resource-profile digests;
- a trusted worker-pool audience, immutable policy ID plus policy digest, and independent
  control-plane purpose label (the label is not the task's private split);
- an authorization ID and independent one-shot dispatch nonce. The nonce is also the
  per-live-instance nonce a future executor must use, so every retry gets a new instance
  identity even though it preserves the prepared-job digest;
- issue, not-before, and expiry times; and
- explicit retry lineage. The first authorization has retry index zero and no parent;
  every retry has a new authorization ID and nonce, names its predecessor and the exact
  digest of that predecessor's claim receipt, preserves every immutable dispatch binding,
  and cannot be issued before its parent is durably claimed. The receipt contains an
  unpredictable worker-generated claim nonce, so an issuer cannot precompute that causal
  link before the parent claim exists.

The signature covers domain-separated canonical JSON bytes. Verification uses an
allowlisted Ed25519 public key whose own validity interval contains the authorization's
complete issue-through-expiry interval. Unknown or revoked keys, malformed encodings, an
invalid signature, and a wrong binding fail before the claim ledger is opened. Production
claim APIs obtain time from the worker clock; callers cannot submit a backdated claim time.
After authentication, the first observed time is durably advanced into the ledger's clock
high-water mark. A backward clock step is rejected, including one between preverification
and ledger creation. Validity is checked again after the SQLite write lock is acquired,
which is the claim's serialization point. An authentic but out-of-window authorization may
therefore create or advance the ledger before failing, but it cannot produce a claim.

The trust-store file or object is itself trusted control-plane configuration; embedding a
public key beside an authorization would not authenticate that key. Its authenticated
distribution, freshness, and rollback protection are out-of-band deployment obligations.
The model supports an overlap window for key rotation and explicit revocation, and receipts
record the exact trust-store digest used. Private signing keys do not belong in this
repository, a worker image, or a replay bundle.

Callers should derive expectations with `dispatch_expectation_for(...)`, not assemble
digests by hand. The helper requires an independently supplied expected manifest digest and
a digest-anchored `LoadedEvaluationJob`, strictly revalidates every loaded blob's identity,
size, and bytes as well as the manifest and execution profile, requires exact
job/environment agreement, checks the local worker-pool audience, and refuses a resource
timeout longer than the job's frozen attempt timeout. The lower-level expectation and
admission APIs remain non-executing cryptographic primitives; a future executor must make
this anchored helper part of its mandatory entry point.

## Signing wire format

The signed message is exactly the following byte concatenation:

```text
42 50 45 00 64 69 73 70 61 74 63 68 2d 61 75 74 68 6f 72 69 7a 61 74 69 6f 6e 00 76 31 00
|| canonical_json(payload)
```

The prefix is `BPE\x00dispatch-authorization\x00v1\x00`. Canonical JSON is UTF-8, sorts
object keys lexicographically, uses `,` and `:` without extra whitespace, emits every model
field including explicit `null`, rejects non-finite numbers, and ends with one LF byte.
Public keys and signatures use unpadded, canonical base64url; alternate encodings are
rejected.

The fixed interoperability vector uses RFC 8032 seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` and this payload:

```json
{"authorization_id":"vector-authorization-1","dispatch_nonce":"0101010101010101010101010101010101010101010101010101010101010101","environment_sha256":"4444444444444444444444444444444444444444444444444444444444444444","execution_profile_sha256":"5555555555555555555555555555555555555555555555555555555555555555","experiment_sha256":"3333333333333333333333333333333333333333333333333333333333333333","expires_at_unix":1700000300,"issued_at_unix":1700000000,"job_manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","not_before_unix":1700000000,"policy_id":"dispatch-policy-v1","policy_sha256":"7777777777777777777777777777777777777777777777777777777777777777","purpose":"validation","request_sha256":"2222222222222222222222222222222222222222222222222222222222222222","resource_profile_sha256":"6666666666666666666666666666666666666666666666666666666666666666","retry_index":0,"retry_of_authorization_id":null,"retry_of_claim_sha256":null,"schema_version":"bpe.dispatch-authorization-payload.v1","worker_pool_audience":"sealed-xdp-workers"}
```

The raw public key is
`11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`, the complete signing-message SHA-256 is
`a6b3f8e4b2b0fb086b0219bafa5e3385e05a9a031c819be3462150cbe469b038`, and the signature is
`H3cuGXbJmKIR5C1LQIRDp3k1K4AK17hsfFs1_OunvX2pZtfRA6jOIw0RyXV_JCdzrTg0m6c23D8V1-sNBwTaDA`.

## One-shot claim

After signature and binding verification, admission writes the authorization to a SQLite
ledger in one immediate transaction. The authorization ID and signed-envelope digest are
independently unique. Concurrent attempts to consume the same authorization therefore
have exactly one winner; every loser fails closed. A committed claim remains consumed
after the process or ledger object is reopened.

The ledger pins rollback-journal `DELETE` mode with `synchronous=EXTRA` on every
connection and rejects the connection if the settings do not read back exactly. SQLite
[documents](https://www.sqlite.org/pragma.html#pragma_synchronous) that `EXTRA` additionally
synchronizes the containing directory after unlinking a committed rollback journal,
closing the power-loss window that remains with `FULL`.

The receipt and ledger retain the exact signing-key ID, trust-store ID and digest, and
dispatch policy ID and digest. Each receipt also contains a worker-generated claim nonce;
its canonical digest is the next retry's required parent reference. The database enforces
that the named parent authorization and parent receipt digest identify the same row, and
permits only one child. Retries form a linear token lineage, not proof that the predecessor
executed or failed; a future result-attestation protocol must authorize retries from signed
infrastructure outcomes.

The ledger requires a caller-owned, non-symlink parent with no group or other write
permission. Every ancestor must be root- or caller-owned and rename-safe; sticky shared
ancestors are permitted. This protects against cross-UID pathname replacement and routine
misconfiguration, not a hostile process with the same UID or root. The future authoritative
service must place the ledger on worker-controlled durable storage, serialize operational
recovery, and keep signing authority outside the execution account.

SQLite documents that `BEGIN IMMEDIATE` starts the write transaction immediately and that
only one write transaction can exist at a time. The implementation combines that property
with uniqueness constraints; it does not treat a pre-transaction lookup as the security
decision. See SQLite's [transaction documentation](https://www.sqlite.org/lang_transaction.html)
and Python's [sqlite3 transaction guidance](https://docs.python.org/3/library/sqlite3.html#transaction-control).

## Typed execution profile

The authorization does not sign an opaque string called “the VM.” Its execution profile
binds the microVM environment, a zero-swap/no-network resource profile, exactly one vCPU
with SMT disabled, Firecracker and jailer binaries, guest agent,
kernel/rootfs/snapshot components, seccomp and jailer configuration, CPU compatibility
identity, and worker-pool audience. `environment.snapshot_sha256` is specifically the
canonical digest of `SnapshotComponents`, not the VM-state file or memory file alone, and
`environment.resource_limits_sha256` must equal the typed resource-profile digest. The
profile remains a declarative contract; possession of matching hashes is not an implemented
readiness or isolation claim.

Phase 1B.1's cgroup-v2 qualification consumes an `ExecutionResourceProfile` only as a
strictly validated, digest-bound configuration input. The resulting report is not signed,
does not consume or verify a dispatch claim, and is not covered by the authorization's
policy digest. It proves exact empty-leaf controller readback at one point in time, not
launch permission or full-profile enforcement. In particular, it creates no process and
does not exercise the profile's CPU-time, wall-time, output, filesystem, or network
controls. See [cgroup-v2 empty-leaf qualification](cgroup-qualification.md).

## Next Phase 1 work

Signed admission closes only the issuer and replay ambiguity. Candidate bytes must not be
executed until all of the following exist and survive adversarial tests:

- production qualification and provisioning of the implemented Linux x86-64 `openat2`
  ingress boundary, including trusted root-descriptor mapping, filesystem fault testing,
  and abandoned-stage recovery;
- production provisioning and native validation of the implemented Phase 1B.1
  cgroup-v2 empty-leaf probe; its unsigned post-removal report cannot authorize launch;
- Phase 1B.2: a bounded native
  `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` supervisor with a fixed inert fixture, fixed
  executable identity and environment, monotonic deadlines, output limits, real resource
  pressure, pidfd lifecycle handling, and race-safe forking-descendant cleanup;
- explicit macOS and native-Linux refusal for authoritative execution;
- a fresh jailed Firecracker process, paused snapshot restore, unique CID/socket/instance
  identity, and a bounded reconnecting vsock protocol; and
- a separately signed result attestation produced only after replay verification and
  deterministic rescoring.

The Ed25519 verification API follows the
[`cryptography` Ed25519 contract](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/):
verification succeeds silently and an invalid signature raises a typed failure. All such
failures are collapsed into BPE's bounded admission error vocabulary.
