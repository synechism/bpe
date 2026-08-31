# Grader threat model

The policy is optimized against, so candidate output is adversarial.

Primary attacks include verifier-passing no-ops, deleting the intended operation, clamping
all work to zero, hard-coding public examples or return values, adding testcase-specific
branches, changing build flags, hiding behavior behind preprocessing, spawning extra BPF
programs, using forbidden helpers/kfuncs/maps/tail calls, exhausting the verifier, and
detecting the test environment. Grader-side attacks also include omitting required checks,
passing a stage with zero assertions, dropping hard or infrastructure-failed tasks from an
aggregate, and replacing every file and hash in a self-consistent replay.

Defenses are layered:

- fixed single-source ingestion and fixed build recipe;
- ELF/BTF/translated-instruction policy checks;
- hidden boundary, activating, randomized, and metamorphic behavior cases;
- semantic obligations over canonical side effects;
- disjoint development/calibration/validation/sealed partitions;
- task-specific adversarial controls required before admission;
- resource limits and disposable microVMs; and
- replay evidence plus suspicious-diff telemetry.

Exact-check scoring contracts, suite manifests, and precommitted experiment manifests
address omission, relabeling, adaptive-sampling, and denominator attacks. Content
addressing detects accidental or partial replay changes. Future official aggregation will
add an authenticated registry entry that binds manifest, evidence, grade, contract, and
policy digests. Bare replay or registry hashes are not signatures, so Phase 0 reports are
structurally nonofficial even when their integrity checks pass.

Active sealed-split replay blobs remain evaluator-controlled because they contain hidden
inputs. Public attestations expose digests, not those inputs; model-facing diagnostics use
only the task's allowed projection.

Release archives are a separate disclosure boundary. The source-distribution build uses an
explicit public allowlist, admits only each task's `public/` tree, and retains private-path
exclusions as defense in depth. CI requires an exact tracked-file/archive manifest and
rejects unsafe names, duplicate members, links, and task-private paths. This does not
make a Git history containing active grader assets safe to publish; repository publication
requires its own explicit review.

Replay writes use a new caller-owned target, create every directory and file inside the
target relative to pinned descriptors, use exclusive file creation, and write the manifest
last as the readiness marker. The published target is then verified against the expected
manifest hash during the write; a final metadata pass checks the writer-created files again.
Failures roll back only recorded writer-created inodes reachable through pinned descriptors,
and leave mismatched entries in place rather than deleting a replacement. Readers must
compare the returned manifest hash with an independently obtained expected hash and reverify
at the point of use, because content addressing does not stop later mutation or authenticate
its issuer.

Portable POSIX APIs do not atomically combine directory creation with opening that new inode,
or metadata comparison with conditional unlink. The replay writer detects changes observed
between its checks, but it cannot guarantee immutability or defeat a hostile process running
concurrently with the same UID; that process can race any later syscall or change owner
permissions. Authoritative runners must write into an isolated worker-owned directory and
hand consumers an independent digest. The writer's return is evidence of an anchored
verification snapshot, not a lease preventing subsequent mutation.

Corpus inputs are adversarial too. The static gate closes each source tree, validates
content digests, blocks declared group/repository-family crossings, and requires every
training-to-evaluation token-n-gram comparison to complete. It still cannot authenticate
claimed provenance or recognize every fork, renamed clone, semantic rewrite, or AST-level
transformation, so `static_audit_passed` is not a training-readiness attestation.

Worker transport is parsed as adversarial bytes. The Phase 0 endpoint permits one bounded
strict-JSON capability request, rejects duplicate/nonfinite/oversized or truncated input,
and correlates the response to both request ID and digest. Hosts must reject nonzero exits,
timeouts, malformed or extra output, unexpected stderr, and correlation mismatches as
infrastructure failures. The protocol has no execution request or arbitrary path/command
field; adding candidate transport requires a new schema and a closed content-addressed
artifact root.

Prepared evaluation bundles are also adversarial filesystem trees. Version 1 accepts only
canonical bounded JSON and the exact `manifest.json` plus `blobs/sha256/<digest>` layout.
It rejects missing and extra entries, symlinks, cross-device objects, non-regular files,
externally hard-linked files, inode replacement during open, content or size mismatches,
and mutation detected during a bounded read. Directories are opened relative to pinned
descriptors and re-enumerated after all reads; consumers receive immutable bytes and never
reopen source paths. The writer likewise retains a private parent descriptor and performs
all staging and publication relative to pinned descriptors. Limits are 256 KiB for the
manifest, 256 blobs, 16 MiB per blob, and 128 MiB total.

Those checks provide integrity, not authority. The manifest fixes
`execution_authorized: false` and `authoritative: false`, and intentionally has no path,
argv, environment, archive, or dispatch surface. Phase 1B.0 therefore accepts a job only
through an exact committed dispatch receipt and signed policy digest. It derives the source
and destination names, applies `openat2` beneath/no-xdev/no-symlink/no-magiclink
restrictions to every untrusted component, reopens type-checked `O_PATH` files through
verified procfs, seals the anchored bytes in memory, and publishes a verified private copy
with `renameat2(RENAME_NOREPLACE)`. There is no source-resolution fallback.

That boundary depends on trusted pre-opened root descriptors, procfs, a local filesystem,
and a dedicated UID without a same-UID adversary. It does not defend against root, a
compromised kernel/supervisor, or a deliberately hostile filesystem, and it has not yet
qualified power-loss durability. Its receipt fixes `execution_started: false` and
`authoritative: false`; it grants no compiler or candidate-process authority. See
[Linux claimed-job ingress](linux-ingress.md).

Phase 1B.1 is a separate cgroup-v2 empty-leaf qualification boundary, not an extension of
that ingress authority. It accepts only a pre-opened delegated-root descriptor and requires
the current effective UID to own a currently childless, empty domain root on cgroup v2.
The exact systemd `user.delegate=1` marker is necessary but is not treated as proof by
itself: ownership and permissions, filesystem magic, root type, `cpu memory pids`
availability and exact subtree enablement, empty process/thread lists, population state,
and lack of child cgroups are all checked independently. Component opens remain beneath
the descriptor with the full `openat2` no-xdev/no-symlink/no-magiclink policy.

The probe creates only an empty leaf. It exactly reads back page-aligned `memory.max`, zero
`memory.swap.max`, `pids.max`, `memory.oom.group=1`, fair-class CPU bandwidth with zero
burst, and zero depth/descendant limits. It writes `1` to `cgroup.kill` only while that leaf
is known to be empty, waits for `populated 0`, verifies identity, removes the leaf name, and
rechecks the root. Because it never creates a descendant, it does not test live signaling,
PID reuse, fork races, pressure behavior, or process reaping. Name removal is not proof
that the kernel has reclaimed every dying cgroup object. The report therefore fixes
process/clone3/pidfd creation, limits exercised, dying descendants reclaimed,
filesystem/network isolation, execution authorization, and authority to `false`.

The report is unsigned point-in-time evidence produced only after the leaf is removed. It
is not ledger-bound, does not reserve the delegation for future use, and cannot be replayed
as launch permission. Phase 1B.2a now provides a separate signed, one-shot intent claim for
one fixed future inert-fixture launcher. The pure-Python boundary accepts no cgroup report,
root descriptor, launcher or executable path, argv, environment, job, or candidate, and it
launches nothing. It does use one locally configured absolute path for its private SQLite
claim ledger. Its receipt fixes `launch_authorized: false`, `execution_started: false`, and
`authoritative: false` even though the signed metadata describes the narrowly permitted
future launcher and fixture child.

The intent claim is necessary but not sufficient for that future process. Phase 1B.2b-0 now
uses a distinct atomic launch ledger, requires the exact committed receipt, and revalidates
the original signed intent, trust role, complete policy preimage, worker and ledger identities,
local bindings, clock floor, and expiry immediately before consuming the sole launch attempt.
Its terminal receipt is explicitly non-launching and nonauthoritative. Phase 1B.2b-1 must
then separately qualify atomic
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` creation, pidfd lifecycle handling, a live
`cgroup.kill`, reaping, and empty cleanup. Bounded signed output/deadlines, real resource
pressure, and race-safe forking-descendant cleanup require later fixed fixtures. A later
terminal result also needs a separate signing domain, attestor role, and durable
result/finalization ledger; it cannot authorize retry or candidate launch. See [cgroup-v2
empty-leaf qualification](cgroup-qualification.md) and [inert-fixture intent
admission](inert-fixture-admission.md).

The Phase 1B.2a one-shot property is local to one configured physical SQLite ledger. The
database persists its worker and claim-ledger identities and admission checks the anchored
path, but those checks do not prevent a same-UID adversary from copying or rolling back the
whole database or an operator from provisioning duplicate physical ledgers with one logical
ID. Authoritative deployment must enforce one durable, non-clonable ledger ownership domain
per worker instance, plus external uniqueness and anti-rollback.

Phase 1A dispatch authorization is a distinct control-plane boundary. The Ed25519 signature
covers domain-separated canonical bytes and binds exact job, request, experiment,
environment, execution/resource profile, audience, control-plane purpose, policy ID and
digest, time window, per-instance nonce, and retry lineage through the exact parent-claim
receipt digest. The public-key trust store is itself out-of-band trusted configuration;
authenticated freshness and rollback protection remain deployment obligations.
Signature and binding failures occur before ledger creation; a valid authorization is then
claimed under SQLite uniqueness constraints in an immediate transaction. Authorization
ID, signed-envelope digest, nonce, claim ID, worker-generated claim nonce, and retry parent
are independently single-use. A durable clock high-water mark rejects rollback between
verification and claim. Retry bindings cannot drift and a retry cannot be issued before its
parent claim. The ledger records trust-store and policy provenance, rejects an unexpected
schema, and requires a private caller-owned parent beneath trusted, rename-safe ancestors.

That ledger is not a same-UID hostile-filesystem boundary or a distributed consensus
system. Authoritative deployment must put it on worker-controlled durable storage and use
one operational ownership domain. The resulting receipt fixes `execution_started: false`
and `authoritative: false`; it must not be confused with a signed execution result.

No regex, source diff, transcript judge, or LLM judge is considered a security boundary.
They may flag suspicious behavior for review, but correctness comes from the fixed binary
contract and hidden observable behavior.
