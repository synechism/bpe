# Grader qualification

`qualify_grader` is the Phase 0 counterexample-ranking gate. It asks whether one frozen
strict grader and reward policy order deliberately adversarial candidates sensibly before
that grader is used for optimization or reporting. It does not execute candidates and it
cannot issue an official benchmark result.

## Frozen authority

The qualification plan binds one dedicated repair suite, environment, harness commit,
grader identity, and reward policy. The supplied suite must contain exactly the task bundles
named by the plan. Every bundle is revalidated from its public/private models, and every
declared `FileRef` must have an exact byte-for-byte, hash-and-size-matching entry in the
bundle's sealed artifact snapshot. Extra, missing, duplicate, and oversized artifacts fail
closed.

Each calibration and validation partition contains at least two tasks. Tasks may not reuse a
normalized repository identity, contamination group, original-program digest, suite cluster,
or artifact digest within a partition, and those identity sets must also be disjoint across
partitions. Repair-task provenance must bind the original-program digest to the sealed
reference source. This is a strong exact-content separation gate; repository normalization
does not authenticate the declared provenance or replace the corpus-level fork, vendoring,
or structural-clone audit.

Every qualification task has exactly one anchor for each role:

- verifier-rejected mutant;
- no-op, operation-deletion, hard-coded-output, and zero-work controls;
- curator-declared, sealed partial-fix candidate;
- reference solution; and
- independently valid alternative.

For this closed matrix, the private grader must seal exactly one valid alternative, one
qualification partial fix, and one control of each required behavior-baseline kind. The
public starter supplies the mutant. The plan cannot relabel or cherry-pick a different
candidate for any role.

## Failure and reward matrix

Every behavioral failure predeclares its exact first failing stage, failure reason, and set
of required functional or semantic checks. The plan closes the witness universe, and the
observed kill matrix must match it exactly. Missing or extra failures, undeclared checks,
timeouts, and a passing exploit all fail qualification. Baseline controls must use the
explicit-hack reason prefix bound by the frozen policy and receive exactly that policy's
hack penalty; equality with the penalty alone is insufficient. A partial fix must not carry
that classification, must receive an intermediate reward, rank above every behavior baseline
for its task, and remain below a full solution. Reference and alternative anchors must both
achieve strict success and the policy's full reward.

Pairwise reward constraints are precommitted, acyclic, and task-local. Every invalid anchor
must rank below a full solution. Every observed margin must be positive and at least the
declared minimum. The scalar reward therefore remains subordinate to the hard success gate
while still being tested for useful optimization pressure.

## Repeated evidence

Every anchor precommits at least two exact `EvaluationJobManifest` digests. Attempts must
match those jobs, use globally distinct request IDs, episode IDs, job manifests, replay
manifests, and restore nonces, and remain independent turn-zero requests. The gate
recomputes every grade and requires repeated behavior—including observation artifact
identities—failed checks, and reward to agree.

The supplied replay manifest is checked with the same structural size limits and
cross-reference digest-metadata consistency rules as the replay subsystem. Its canonical event
reference, evidence/grade/contract/policy references, candidate reference, and external
anchor fields must match the attempt. The report retains exact job, restore, evidence,
grade, and replay digests for every repeat.

## Phase 0 boundary

The receipt is deliberately `provisional`, `authoritative: false`. Phase 0 does not:

- execute the candidate or verify the candidate blob from a prepared job bundle;
- load and validate a complete replay directory or its artifact bytes;
- authenticate the evaluator or prove that a trusted worker restored a fresh snapshot;
- prove that calibration happened before validation was revealed; or
- enforce one-shot access to the validation partition.

Plan and job digests make post-freeze changes detectable, but they cannot establish when the
freeze occurred. An authoritative workflow therefore needs an externally witnessed freeze,
controlled validation release, authenticated evaluator attestations, verified replay
directories, and per-run snapshot receipts without weakening this matrix.
