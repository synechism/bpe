# Native inert-launcher qualification evidence

`bpe.linux-inert-launcher-native-qualification-report.v1` is the replayable evidence
contract for the fixed privileged Linux x86-64 launcher gate. It is separate from the
process-free artifact-preflight receipt: preflight proves that trusted launcher bytes were
copied into a sealed executable memfd, while native qualification records what one
disposable live-kernel probe observed when fresh duplicates of those exact bytes ran.

The report is diagnostic evidence only. It fixes execution authorization, candidate and
evaluation-job access, authoritative status, official grading, resource-pressure coverage,
forking-descendant coverage, signed dynamic deadline/output coverage, filesystem and network
isolation, and production orchestration to `false`. Its literal status is
`native_probe_passed_unsigned`, not a general readiness claim. Five launcher processes and
the two expected built-in no-exec fixture children did run; no fixture child performed
`exec`. Those five evaluator-only executions do not use production launch admission and
consume zero production launch attempts; the nested preflight receipt remains the earlier
point-in-time receipt whose one-shot production attempt was not consumed. No serialized
report is a launch token, retry token, artifact handle, or proof that a retained descriptor
still exists.

The separate [atomic fixed-fixture orchestrator](inert-fixture-orchestration.md) is now
implemented, but it does not widen this report. Native qualification's five cases remain
evaluator-controlled launcher tests that intentionally bypass the production launch ledgers;
the report therefore continues to fix `production_orchestration_qualified: false`. The
trusted workflow exercises the installed production orchestrator in its separate cgroup
gate, with its own signed intent, private ledgers, canonical result replay, and cleanup
assertions; those observations are not imported into this five-case report.

## Fixed case set

Version 1 admits exactly these cases, in this order:

1. `success` — the complete five-frame success transcript, exact `0x1ff` achieved mask,
   fixture-child identity, and normal pidfd/cgroup lifecycle;
2. `extra-fd` — an inherited descriptor 257 is rejected at descriptor validation;
3. `inbound` — one prequeued control byte causes startup failure and an empty transcript;
4. `peer-close` — a peer closed before execution causes protocol failure and an empty
   transcript; and
5. `emergency-cgroup-kill` — an evaluator-only outer seccomp filter returns `EPERM` for
   `pidfd_send_signal`, requiring the exact `HELLO`, `CHILD_READY`, `ERROR` transcript and
   `0x1c3` mask before external cleanup checks pass. Under the fixed-child, trusted-kernel,
   single-writer assumptions this evidences the emergency cleanup outcome, but the
   transcript does not independently prove the return from the `cgroup.kill` write.

The case-set identifier, injection contract for each case, and order are literals. A report
cannot substitute a different adversary, omit a case, append an easier case, or relabel an
observation.

## Replay, not asserted interpretation

Each case retains the exact bounded `SOCK_SEQPACKET` payload bytes together with message and
control truncation flags, ancillary-data observation, launcher PID, process return code, and
whether peer EOF was observed. The report also carries a domain-separated transcript digest
and a normalized parser projection.

Validation reconstructs `InertNativeSocketRecord` values and reruns
`parse_inert_native_transcript`; it does not trust the stored projection. The success,
extra-descriptor, and emergency cases must reproduce their exact parsed states. The inbound
and peer-close cases must make the parser reject their exact fixed raw input; their stored
rejection labels are derived from the case/input contract rather than parser exception text.
An empty record list is never fabricated into a successful or error transcript. A parser
change that alters the judgment therefore requires a new report contract or causes old
evidence to fail replay.

The generated JSON Schema validates only the serialized shape. It cannot express the fixed
case order, cross-layer digest equalities, raw-transcript replay, or complete cleanup
invariants. Consumers of untrusted bytes must use
`validate_inert_native_qualification_report_bytes()`; schema validation alone never admits a
report.

For every case, qualification also requires a fresh duplicate of the production sealed
artifact with the expected digest, complete seal mask, read-only status, and close-on-exec
state. After the launcher exits, the probe must prove exact launcher reap, no reparented
descendant, empty `cgroup.procs`, `populated 0`, and successful leaf removal. Best-effort
evaluator fallback cleanup invalidates qualification even if the final filesystem happens to
look empty.

## Relationship to atomic orchestration

Production orchestration has stricter admission and ordering than the case controller. It
must reauthenticate the signed intent and exact claim, seal and stage the artifact, validate
a dedicated single-threaded childless host, durably consume and verify the launch-attempt
receipt, and only then retain and hand off a cgroup. Its `posix_spawn` call exposes exactly
`/dev/null` on descriptors `0..2`, the control socket on `3`, the cgroup leaf on `4`, one
fixed `argv[0]`, and an empty environment. Ambiguous receipt recovery never reaches spawn.

The production result preserves at most eight bounded raw socket records and reruns the same
strict transcript parser used here. It additionally binds the full fixture/cgroup policies,
launch-attempt receipt, shared fixture/cleanup/total deadline observations, retained-leaf
identity, and terminal cleanup facts. That result is also unsigned and nonauthoritative; it
does not convert this qualification report into provenance or vice versa.

The production controller has no `PDEATHSIG`. Its dedicated-process and child-subreaper
checks support normal terminal cleanup, not crash recovery. An outer systemd unit or PID
namespace must independently contain and reap work after abrupt controller death, when the
only durable local evidence may be the launch-ledger tombstone.

## Provenance and finalization

The report binds the source revision and a canonical source-content manifest; both the
trusted native controller and upstream CI workflow, probe, parser, report schema and
implementation, artifact-preflight implementation, lockfile, launcher source, protocol,
build recipe, seccomp headers, and wire implementation; the built wheel and launcher; the
native runner, kernel, namespace, container, and invocation observations; the complete
artifact-preflight receipt; and the fixed outer-fault profile. The whole tracked-tree
manifest is derived from the exact commit's regular Git blobs, records their modes and
recomputed Git blob identities, and copies the critical source closure from those blob bytes
rather than from the mutable checkout. That closure includes every committed file beneath
`src/bpe`, including package data. Replay maps those source paths to their installed paths
and requires one byte-for-byte content-tree identity across the commit, rebuilt wheel, and
runtime package, with no missing or extra runtime package files. Before either container can
import BPE, the trusted controller rejects any wheel member outside the exact package and
fixed `bpe-0.1.0.dist-info` file sets and compares every package member to its commit blob.
Container Python starts with `-S`, disabling `site` and `sitecustomize`, and the report
producer admits only the exact installed package, metadata, and generated entry-point file
set beneath `/runtime`; unowned or archive-root startup payloads invalidate the run. Replay
also requires the dependency root to equal the files claimed by its locked distributions.
Preparation accepts and removes only uv's exact empty `.lock` file and CFFI's exact unused
`bin/cffi-gen-src` installer output before the dependency tree becomes read-only; any other
unclaimed file invalidates the run.
Replay also reconstructs the exact canonical workflow
provenance document from the report's cross-layer fields and requires its byte length and
digest to match the read-only provenance mount. These bindings make accidental mixing and
replay drift visible. They do not authenticate the issuer.

The privileged probe accumulates evidence in memory. A qualified report may be published
only after all leaves are removed, PID 1 is restored, the manager cgroup is empty and removed,
the original and duplicate artifact descriptors are closed, and the production artifact
handle reports closed. The final canonical file is created once at a fixed output location;
any mismatch, ambiguous cleanup, use of evaluator fallback cleanup, or pre-existing output
causes the run to fail without a qualified report.

On failure only, the controller streams the disposable container output through a fixed-size
16 KiB tail and emits a single GitHub error annotation containing a bounded, ASCII-escaped
suffix and the original container exit status. The full output is neither uploaded as an
artifact nor treated as qualification evidence; the bounded annotation is retained in Actions
metadata and logs. The container has no network and receives no GitHub credential or secret
mount, and its daemon-side logging driver is disabled so the uncapped stream is never spooled
outside the bounded collector.

The privileged producer runs only in a separate `workflow_run` controller after `CI`
successfully completes for a same-repository push to `main`. Its job-level guard requires
the downstream repository, event, default-branch ref and controller SHA to match the exact
upstream workflow name, path, event, branch, repository, conclusion and head SHA. It checks
out that SHA without persisting credentials, rebuilds in a fresh cache-free lane, and does
not consume upstream artifacts. The trusted controller never checks out or executes a pull-
request ref. The ordinary pull-request workflow contains no native-qualification producer
or project-configured privileged-container step; repository and runner policy remain the
external enforcement boundary for arbitrary workflow changes.

The fresh-history public projection carries the two controller workflows and exactly the two
native probe programs as a closed operational overlay. The package source distribution still
excludes `.github/` and `tests/`. Publication copies the overlay from the same reviewed commit
as the audited source archive and rejects all other workflow and test paths, so every critical
source path required by the native controller is reachable on public `main` without exposing
the evaluator-private suite or task graders.

## Authenticity and durability boundary

The version 1 report is self-consistent but unsigned, provenance- and
freshness-unauthenticated, nonauthoritative, and not durable merely because a workflow or
Actions artifact contains it. Its 256-bit random nonce is a correlation value, not a trusted
freshness proof. Future admission must require an external
attestation over both the launcher subject and complete report, verify protected repository,
workflow, commit, and run identity, and retain the report plus verification bundle in an
append-only or content-addressed durable store keyed by `qualification_id`. Hardware-backed
runner attestation is a separate requirement; without it, the CI supervisor and kernel remain
trusted assumptions.

This repository currently contains the contract and internal gate integration, not a
published native qualification claim. Code or workflow presence is never evidence, and an
ARM/macOS development run cannot produce this report.
