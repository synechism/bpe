# Grading contract

The grader is a measurement system, not a test-script afterthought. BPE keeps three
concepts separate:

1. **Strict benchmark success** answers whether the candidate actually solved the task.
2. **Diagnostic stage evidence** explains how and where it failed.
3. **Training reward** supplies a dense signal to the optimizer and can be revised by
   rescoring a sealed evidence snapshot.

## Authoritative success rule

For every task:

```text
strict_success =
    ingest_pass
    AND compile_pass_with_fixed_recipe
    AND object_policy_pass
    AND real_kernel_verifier_accept
    AND every_required_functional_assertion_pass
    AND every_required_semantic_and_anti_hack_obligation_pass
```

The benchmark score for a task is exactly `1` when this conjunction is true and `0`
otherwise. An infrastructure failure is neither: it is incomparable and must be retried.
Verifier acceptance alone earns no benchmark credit.

The frozen task bundle produces a scoring contract that enumerates the exact check IDs,
stages, and required status the scorer will accept. Object-policy, functional, and
semantic stages must each contain at least one required check. Evidence must match that
manifest exactly: missing, duplicate, unexpected, or vacuously empty required checks are
grader failures, never successful evidence. The contract digest is bound into the grade
and replay so a worker cannot redefine success by omitting a difficult assertion.

The primary report is `pass@1`. Independent-sample `pass@k` uses
`1 - C(n-c,k) / C(n,k)`. An interactive three-turn repair episode is reported separately
as success-by-turn; it is not `pass@3`.

Aggregation is also fail-closed. Before generation, an experiment manifest freezes the
suite, model artifact, distinct checkpoint artifact for every training seed, exact
generation-seed plan and sample count, sampling config, reward-policy digest,
grader/environment identity, and reported values of `k`. Every suite task must have exactly
that many comparable samples for every seed. Infrastructure failures, missing tasks, and
incomplete task/seed cells stop publication instead of disappearing from the denominator.
Model and checkpoint artifact digests, sampling configuration, episode, training seed,
sample index, generation seed, and turn index are bound into the replayed request;
conditions cannot be relabeled when reporting. Repair suites also freeze their required
root-cause taxonomy and must contain at least one task for every declared category.

## Why the score is a hard gate

eBPF gives us a formal safety oracle and deterministic behavior checks. Unlike a visual
similarity problem, there is no principled reason to average away a transient wrong map
update, packet mutation, return code, or emitted event. We keep assertion fractions as
training diagnostics, while requiring every critical assertion for capability claims.

Source edit distance is never a correctness criterion. Equivalent fixes must receive full
credit. Source deletion ratio and suspicious constants are audit telemetry only; the
security boundary is the object contract plus hidden differential/property tests.

## Reward policy v1

The stored policy in `policies/reward-v1.json` is deliberately subordinate to the strict
metric:

| First failing stage | Reward |
|---|---:|
| malformed/unsafe response | -1.0 |
| compile | -0.5 |
| object policy | -0.25 |
| verifier | 0.0 |
| functional | up to 0.10 by required-check fraction |
| semantics/anti-hack | 0.10–0.60 by required-check fraction |
| all pass | 1.0 |
| explicit hack classification | -1.0 |

This caps a verifier-passing no-op at a small signal. The exact weights are training
mechanics, not benchmark points.

## Task-admission gate

A task cannot join training or evaluation until a pinned microVM run proves all of the
following:

1. The original/reference compiles, loads, and passes every behavior and obligation.
2. The mutated source compiles and is rejected by the verifier.
3. Reverting the mutation restores success.
4. At least one independently written equivalent fix also scores perfectly.
5. No-op, operation-deletion, hard-coded-output, and zero-work controls fail.
6. Boundary, activating, negative, and randomized hidden witnesses exercise the behavior.
7. Repeated fresh-snapshot runs are deterministic.
8. Provenance, license, split, mutation, and environment digests are complete.
9. Cilium, xdp-tools, and bpftime provenance is excluded from training.
10. The public projection contains no reference, hidden case, root-cause, or anti-hack data.

The task linter performs the static subset and emits `DYNAMIC_ADMISSION_REQUIRED`. In
addition, `bpe task admission verify` now validates a complete, precommitted evidence
matrix for repair tasks. It recomputes every grade, checks replay bindings and the exact
role matrix, and requires deterministic reference/revert behavior. That receipt is always
`provisional` and `authoritative: false`: the command consumes supplied microVM-shaped
evidence but does not run a microVM, verify a complete replay directory, authenticate its
issuer, or prove a distinct snapshot restore per attempt. See
[the provisional admission contract](admission.md).

Static leakage linting closes both artifact trees, rejects shared content digests and known
private identifiers, and compares substantial UTF-8 artifacts as normalized token streams.
The comparison ignores C comments, line splices, and formatting, and also catches a complete
private artifact embedded inside a longer public artifact. A second textual view retains
comment bodies while discarding their delimiters, so copying the answer into public line or
block comments is still a leak. It deliberately does not use a fuzzy similarity threshold:
a repair starter is expected to be close to its reference, and token changes that implement
the mutation must not be mistaken for disclosure. These checks are defense in depth; they do
not replace trusted task review or the dynamic admission gate. The linter preflights a
deterministic comparison-work budget and rejects an over-budget task instead of performing a
partial or adversarially expensive leakage scan.

Corpus-level contamination is handled separately by frozen closed-tree manifests and a
blocking exact/normalized-token/token-n-gram audit across training and every
evaluation-like split. A pass is explicitly static-only and cannot rule out forks,
vendored or renamed code, or semantic/AST clones. See
[the contamination gate](contamination.md).

## Grader iteration protocol

The process is adapted from GBA Eval's measurement work:

1. Write the capability statement and hard success conjunction first.
2. Build adversarial anchors: mutant, no-op, deletion, hard-coded behavior, partial real
   fix, original, and an alternative valid fix.
3. Blind-rank ambiguous candidate behavior when expert judgment is genuinely necessary.
4. Tune free parameters only on a calibration split.
5. Validate once on different repositories/program families and candidate-producing
   models.
6. Freeze the rubric, task manifest, environment, and sealed split.
7. Put a new grader version in a new leaderboard column; never silently compare versions.
8. Red-team every revision under optimization pressure.

The executable Phase 0 subset is [`qualify_grader`](grader-qualification.md). It validates a
dedicated suite of byte-sealed, identity-disjoint calibration and validation tasks; requires
an exact per-task mutant/control/partial/reference/alternative matrix; checks exact witness
kills; and verifies predeclared reward orderings over repeated job-bound, replay-shaped
evidence. Its receipt remains provisional because no Phase 0 command runs or authenticates
a microVM evaluation, verifies complete replay bytes, or proves calibration-before-validation
chronology.

The key lesson from [grading iteration](https://gbaeval.com/blog/grading-iteration/) is not
to copy SSIM; it is to reject metrics that misorder deliberately constructed counterexamples.
The [environment-design post](https://gbaeval.com/blog/environment-design/) motivates a
useful black-box oracle and public development cases without exposing the hidden grader.
The [replay-scoring post](https://gbaeval.com/blog/replay-scoring/) motivates lockstep inputs,
step-level evidence, disjoint calibration/validation candidates, and an interpretable
aggregate.

## Functional replay contract

An authoritative Phase 1 runner will start candidate and reference from identical fresh
snapshots and give them the exact stored inputs. For XDP/TC tasks, the planned first
implementation will use `BPF_PROG_TEST_RUN` with `repeat=1` and a fresh object/maps per case.
Canonical evidence will record:

- return value;
- output packet and context bytes;
- sorted map key/value state and deltas;
- ordered ring-buffer or perf-event records; and
- declared persistent counters.

Only task-declared nondeterminism—such as timestamps, PIDs, addresses, or unordered map
iteration—will be eligible for normalization, and both the normalizer version and content
digest will be part of the grader identity.

The first required assertion divergence and expected/actual artifact hashes will be retained.

## Phase 0 qualification boundary

The strict score describes the evidence supplied to the scorer; it does not by itself
establish an official measurement. A future authoritative result will additionally require:

1. the complete frozen suite and precommitted experiment manifest;
2. distinct, content-addressed checkpoints and exact sample plans for every training seed;
3. the pinned disposable microVM environment and matching grader identity;
4. a valid content-addressed replay containing the candidate, exact inputs, and evidence;
5. a trusted registry entry binding the manifest, evidence, grade, scoring-contract, and
   reward-policy digests, with the registry itself externally anchored; and
6. no infrastructure or unsupported outcome in an eligible task/seed cell.

The repository's manifest digest is an integrity primitive, not an issuer signature. A
self-consistent replay supplied without an independently obtained expected digest is
unanchored. More importantly, **Phase 0 cannot emit an official report at all**: its worker
does not execute candidates against the real pinned kernel, and its registry model does not
itself verify an authoritative evaluator's signed or append-only publication channel. Even
a complete microVM-shaped record with a matching externally supplied registry digest is a
strict pipeline-validation result with `official: false`. Native Linux, synthetic, and
unanchored evidence remain explicitly diagnostic.

## Reporting

The Phase 0 report schema includes exact `n/N`, pass@1/pass@k settings, each training seed
and checkpoint, stage breakdown, root-cause and program-type slices, and a hierarchical
Bayesian interval with shared training-seed and original-program cluster weights. Phase 3
will extend operational reporting with latency, verifier calls, tokens, and compute before
publishing model results.

The 75-task bpfix-bench average is preserved for comparability. The larger mutation suite
will additionally macro-average the 12 root causes so easy, abundant mutations cannot
dominate. Generation and unseen-helper/program-type generalization remain separate
headline metrics until a composite has been independently justified.
