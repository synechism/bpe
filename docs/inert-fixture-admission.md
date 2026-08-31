# Inert-fixture intent admission

Phase 1B.2a implements a pure-Python control-plane boundary for one future fixed inert
fixture. It authenticates a short-lived Ed25519 intent, binds it to trusted local policy,
and consumes it once in an independent durable ledger. It does **not** open a launcher,
create or configure a cgroup, call `clone3`, obtain a pidfd, or start any process.

For these admission APIs, the spawned one-shot launcher, its fixed descriptor layout and
empty environment, and the built-in no-exec fixture remain signed **metadata only**. A
separately compiled native launcher source artifact now implements that fixed state machine.
Python authenticates and seals its exact configured bytes without invoking it, and a
separate blocking privileged native x86-64 Linux CI probe is configured to exercise its
fixed live-kernel lifecycle. Qualification requires that probe to pass on a native x86-64
host; its presence alone is not evidence. Atomic Python launch orchestration is still absent.
A successful admission receipt has status
`claimed_not_started` and fixes
`launch_authorized`, `launch_attempt_consumed`,
`process_created`, `execution_started`, and `authoritative` to `false`.

## Closed intent surface

`InertFixturePolicy` fixes one Linux x86-64 design:

- purpose `inert_fixture_qualification` and operation
  `qualify-clone3-inert-noexec-v1`;
- one spawned, one-shot launcher artifact ID and SHA-256, plus the launcher seccomp-policy
  ID and SHA-256;
- literal launcher, IPC, descriptor-layout, argv/environment, fixture, `clone3`, pidfd,
  wait, deadline, and cgroup-cleanup protocol versions;
- one typed `ExecutionResourceProfile` and its exact canonical digest;
- a fixture deadline, a fixed five-second cleanup deadline, and their exact sum;
- one worker-pool audience, worker-instance identity, configured claim-ledger identity,
  and a distinct future launch-ledger identity;
- exactly one ledger-local claim and one future launch attempt, with retries forbidden; and
- narrowly scoped signed metadata permitting only the fixed launcher and built-in fixture
  child. Child `exec`, an external fixture executable, candidate access, evaluation-job
  access, and authoritative readiness are all forbidden.

The payload repeats the security-critical launcher artifact, seccomp policy, fixed fixture,
resource, audience, worker, claim-ledger, distinct launch-ledger, delegated-root, deadline,
and one-shot bindings. Its policy digest also commits to the policy-only fixed descriptor,
argv/environment, IPC, syscall, and cleanup metadata. A delegated-root ID is only a trusted
deployment label in Phase 1B.2a; the current APIs accept no cgroup descriptor and inspect no
delegation.

The public surface accepts no launcher path, command, caller-selected argv or environment,
job, candidate bytes, external fixture executable, dispatch authorization or receipt,
Linux-ingress receipt, or Phase 1B.1 cgroup-qualification report. In particular, an unsigned
post-removal cgroup report cannot be converted into an inert-fixture claim or launch token.

## Trusted expectation

Callers derive `InertFixtureIntentExpectation` with
`inert_fixture_intent_expectation_for(...)`. The helper strictly revalidates the dedicated
policy and requires independent trusted anchors for:

- the complete immutable policy preimage and its digest;
- worker-pool audience, worker-instance ID, configured claim-ledger ID and absolute path,
  distinct future launch-ledger ID, and delegated-root ID;
- launcher artifact ID and digest; and
- launcher seccomp-policy ID and digest.

It retains that complete policy preimage and derives every expectation field from it.
Passing a self-consistent policy beside an intent does not make the policy trusted; authentic
distribution, freshness, and rollback protection for the policy and trust store remain
deployment obligations.

`verify_inert_fixture_intent(...)` is read-only. It requires the dedicated intent and trust
store types, exact expectation equality, a currently valid time, one matching non-revoked
key, and a key-validity interval that covers the intent's complete issue-through-expiry
interval. The intent may live for at most 15 minutes.

## Signing format

The signing message is exactly:

```text
BPE\x00inert-fixture-intent\x00v1\x00 || canonical_json(payload)
```

Canonical JSON is the repository's UTF-8, sorted-key, compact representation with one final
LF. The envelope separately carries the exact payload digest. Public keys and signatures
must be canonical unpadded base64url, and malformed or alternate encodings fail closed.
The role-specific trust store rejects duplicate key IDs and duplicate public keys and
records validity and revocation state. Private signing keys are not part of this repository
or the worker-side contract.

The contract test
[`test_inert_fixture_signing_wire_format_has_a_fixed_ed25519_vector`](../tests/unit/test_inert_fixture.py)
is the interoperability vector and fixes every payload field. It uses the RFC 8032 test seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`
for test purposes only, with:

- public key, unpadded base64url:
  `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`;
- SHA-256 of the complete domain-prefixed signing message:
  `b0bbb31babe335c1e3d681b0eca4e937648fe706afaa4e28d8f6be61fda4972d`; and
- signature, unpadded base64url:
  `8MW8GkqQ4jHt2k7UgXN9d2ydlyeK2cweaVVmpPlZAoVySjCB9oh5PhLxZuGiQp_-8_17tNeAO0MSTb74t7bsDg`.

The seed is public test material and must never be configured as a deployment key.

## Durable one-shot claim

An operator must first create a new ledger explicitly with
`InertFixtureIntentLedger.provision(...)`, binding the physical database to one configured
worker-instance ID and claim-ledger ID. Provisioning refuses an existing path. The normal
constructor only opens an already-provisioned, nonempty exact database; admission never
silently recreates a missing ledger. `admit_inert_fixture_intent(...)` accepts that configured
ledger object, checks its exact identity and anchored absolute path before any query or clock
mutation, authenticates the intent, and then `claim_intent(...)` reverifies it using the
worker clock.

If provisioning reserves the path with exclusive creation but a later durability or schema
step fails, it may leave a private fail-closed file in place. It never deletes or replaces
that path automatically. Before retrying, an operator must confirm that provisioning failed,
that no worker is using the path, and that `lstat` still identifies the exact expected
caller-owned, single-link regular file with mode `0600`; only then may the operator remove
that exact path and explicitly provision it again. If any identity is uncertain, preserve
the file and investigate rather than deleting it.

The ledger requires an absolute path under a caller-owned, non-symlinked parent with mode
that grants no group or other write access. The database itself must be a caller-owned,
single-link regular file with exact mode `0600`. Ancestors must be root- or caller-owned and
rename-safe; sticky shared ancestors are permitted.

The SQLite database has a distinct application ID and exact version-2 schema. Every write
connection requires rollback-journal `DELETE` mode and `synchronous=EXTRA`; all connections
enable foreign keys and disable trusted schema, while recovery uses SQLite `mode=ro` plus
`query_only`. Integrity, schema objects, columns, indexes, application ID, user version, and
the singleton identity/clock row are checked exactly within one database transaction
snapshot. The clock high-water must never trail any committed subject-reservation timestamp.
These checks
protect against routine corruption and misconfiguration, not root, a hostile same-UID
process or filesystem, distributed claims, or rollback of the complete ledger file.
Exact validation includes full integrity and committed-reservation timestamp scans, so this
ledger is deliberately a low-volume qualification boundary, not the per-candidate rollout
queue.

Claiming uses `BEGIN IMMEDIATE`, validates the schema after taking the write transaction,
and checks the worker time again at the serialization point. A durable clock high-water
mark rejects backward movement. Before validating a caller claim ID or constructing any
worker nonce or receipt, it durably reserves the exact signed-envelope digest; signed intent
IDs and nonces are unique across those reservations. Any later caller-ID collision, nonce or
receipt collision, receipt-construction failure, or storage collision commits that subject's
reservation as a terminal tombstone. It does not reserve a caller-controlled ID globally,
so one caller cannot poison unrelated authenticated subjects. Successful claim IDs,
worker-generated nonces, and receipt digests remain independently unique. Concurrent reuse
has one winner, a tombstoned subject cannot retry with a different identity, and
`claim_count()` counts all consumed reservations rather than only receipts. An out-of-window
attempt may advance the durable clock but cannot reserve the subject.

The claim row also stores the bounded canonical receipt bytes. If the process dies after a
durable commit but before returning the receipt, or if commit completion is otherwise
ambiguous, `recover_committed_receipt(...)` reverifies the original signed intent, trust
store, and local expectation before parsing those bytes. It requires canonical encoding,
the stored digest, authenticated intent/trust identities, and the exact committed row to
all agree. A matching reservation without receipt bytes is reported as terminally consumed,
not as permission to retry. Recovery is read-only evidence reconstruction, not another
claim or a launch. Callers must attempt recovery before classifying an ambiguous outcome.
Writable connections use SQLite `mode=rw`; deletion of an initialized ledger is an error,
not permission to silently create a replacement database.

The one-shot guarantee is local to this one configured physical ledger. Copying or rolling
back that database, or provisioning multiple databases with the same logical ledger ID,
falls outside the SQLite boundary. Deployment must give each worker instance one durable,
non-clonable ledger ownership domain and enforce uniqueness and anti-rollback externally
before treating a claim as operational evidence.

SQLite documents the relevant [`BEGIN IMMEDIATE` transaction
semantics](https://www.sqlite.org/lang_transaction.html) and
[`synchronous=EXTRA`](https://www.sqlite.org/pragma.html#pragma_synchronous) durability
behavior.

## Receipt boundary

`InertFixtureIntentClaimReceipt` records the exact intent, payload, signing key, trust store,
policy, audience, worker, configured claim-ledger, distinct launch-ledger, delegated-root,
launcher, seccomp, fixture, resource, deadline, and claim identities.
`verify_committed_receipt(...)` recomputes its canonical digest and requires exact equality
with the committed ledger row and actual configured ledger identity.

That method proves only that this precise prelaunch receipt was committed. The receipt
explicitly says:

- the signature and one-shot claim were verified and committed;
- the signed metadata permitted the one fixed launcher and fixture child;
- a separate launch ledger is required;
- no launch attempt has been consumed or authorized;
- no launcher artifact was accessed and no launcher or fixture process was created;
- no child `exec`, external fixture, candidate, or evaluation job was accessed; and
- execution has not started and the receipt is nonauthoritative.

Neither `verify_committed_receipt(...)` nor possession of the receipt revalidates the
original signature for a later launch. The claim ledger deliberately has no process-start
state and cannot be repurposed as a launch ledger.

## Separate launch-attempt consumption

Phase 1B.2b-0 implements the required second one-shot boundary in
`bpe.inert_launch`. It is still process-free. The module accepts no launcher path or bytes,
command, argv, environment, cgroup descriptor, fixture selector, candidate, evaluation job,
or process callback.

Callers derive `InertFixtureLaunchExpectation` with
`inert_fixture_launch_expectation_for(...)`. The launch expectation retains and strictly
reconstructs the complete trusted intent expectation, then adds the exact existing absolute
launch-ledger path. Worker-instance, claim-ledger, and launch-ledger identities must equal
the signed intent bindings, and claim and launch ledgers must remain distinct.

An operator must explicitly create that physical database with
`InertFixtureLaunchLedger.provision(...)`. The normal constructor is open-only and refuses
missing, empty, differently identified, permissively writable, linked, or noncanonical
files. Its SQLite application ID and exact schema differ from the intent-claim ledger. It
uses the same private-file, exact-schema, `DELETE` journal, `synchronous=EXTRA`, integrity,
transaction-snapshot, clock-high-water, and explicit failed-provisioning recovery rules
described for the claim ledger.

`admit_inert_fixture_launch_attempt(...)` requires all of the following again:

- the original dedicated signed intent and role-specific trust store;
- the complete trusted intent and launch expectations;
- the exact configured claim ledger and exact committed claim receipt; and
- the separately configured launch ledger plus a nonzero caller attempt ID.

It revalidates the original signature and complete policy, recovers and compares the exact
committed claim receipt, and checks every worker and ledger binding before launch-ledger
mutation. Inside `BEGIN IMMEDIATE`, it validates the complete launch-ledger snapshot, samples
the worker clock at the serialization point, and requires that time to be no earlier than
verification, claim time, or the durable high-water mark and strictly earlier than intent
expiry. It advances the durable clock before recording an expiry rejection. Before
validating the caller attempt ID or generating receipt material, it reserves the exact
committed claim-receipt digest; the committed intent and claim identities are unique across
reservations. Any later caller-ID, worker-nonce, receipt, construction, or storage collision
leaves only that authenticated subject terminally consumed. Caller-controlled attempt IDs
do not become global tombstones, while successful attempt IDs, worker nonces, and receipt
digests remain independently unique. No collision or concurrency path lets the consumed
subject retry with a new identity, and `attempt_count()` counts reservations including
tombstones.

The committed `InertFixtureLaunchAttemptReceipt` embeds the exact claim receipt and records
status `launch_attempt_consumed_not_started`. It fixes original reauthentication, committed
claim verification, serialized clock verification, separate-ledger use, and attempt
consumption to `true`. It fixes retry permission, launch authorization, launcher/fixture
process creation, child exec, candidate/job access, execution, and authority to `false`.
Possessing or replaying it cannot start a process.

If commit completion is ambiguous, `recover_committed_receipt(...)` reauthenticates the
original inputs without turning expiry into a retry, reads only canonical bounded receipt
bytes, checks their digest and every nested binding against the exact row, and returns that
same terminal evidence. A matching reservation without receipt bytes is an explicit terminal
consumption outcome. A consumed attempt is never retried, including after a caller crash.
The one-shot property is local to one configured physical launch ledger; deployment must
prevent whole-file rollback, cloning, and duplicate provisioning for the same logical ID.

## Required native boundary

The orchestration boundary must safely preflight the host, trusted launcher bytes, and exact
seccomp filter before consuming the launch attempt. The process-free [immutable launcher
artifact preflight](launcher-artifact-preflight.md) now provides that sealed executable-FD
handoff. A blocking privileged native probe is configured to exercise the exact fixed
launcher lifecycle, and qualifies it only when it passes on a native x86-64 host. The
pending atomic orchestrator must then consume that attempt before creating a leaf cgroup or
any process and treat every later failure or ambiguity as terminal.
Neither the original claim receipt nor the launch-attempt receipt can be accepted as a
standalone launch token.

The repository now contains a separately compiled, single-threaded, one-shot C launcher
whose child follows one built-in fixed no-exec fixture state machine. It must qualify the
actual `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)`, pidfd stop/exit observation and reaping,
one live `cgroup.kill`, and empty cleanup first. The configured native gate also has an
evaluator-only inherited seccomp case that denies both `pidfd_send_signal` attempts with
`EPERM`; only a successful native run with the canonical `0x1c3` error transcript plus
external reap/empty/removal checks qualifies emergency cleanup through `cgroup.kill`.
Signed wall/output deadlines, real
controller pressure, and forking-descendant cleanup require later fixed fixture protocols
and cannot be inferred from that first slice. Its static-PIE build, fixed seccomp filter, and
result-only wire parser have compile and unit checks plus a configured blocking privileged
native x86-64 live-kernel gate. Only a successful native run supplies qualification
evidence. The
process-free Python preflight can retain its exact sealed executable fd, but no atomic Python
orchestration path launches it yet. The Phase 1B.2a launcher kind, artifact and seccomp digests, fixed
`argc == 1`/empty-environment design, descriptor layout, IPC method, and fixture protocol
remain commitments until the complete launch-orchestration/result boundary is reviewed;
their presence alone is not evidence that any of it ran.

A terminal result needs another signing domain and result-attestor trust role, plus a
separate durable result or finalization ledger. It must bind the original intent, committed
claim and launch-attempt identities and exact launcher/fixture/resource policy. Such a
result is evidence, cannot authorize a retry or candidate launch, and remains
nonauthoritative. Candidate execution, executable/argv/environment/dynamic-loader
qualification, filesystem or network isolation, and official grading remain later,
separately reviewed boundaries.
