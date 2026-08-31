# Provisional dynamic task admission

Task admission is a measurement of the grader as much as it is a measurement of the task.
The public mutant must fail for the intended reason, valid solutions must pass, and
task-specific anti-hack controls must be rejected at the behavior stage they are designed
to test. BPE freezes that claim before looking at run results and checks an exact evidence
matrix afterward.

The Phase 0 implementation is deliberately a **receipt verifier**, not an execution or
trust oracle. A successful report always has:

```text
phase: phase0
status: provisional
authoritative: false
fresh_snapshot_instances_verified: false
```

Those fields are literals in the schema. Supplying internally consistent evidence can
never turn a Phase 0 receipt into an authoritative admission.

## Frozen plan

An admission plan precommits the exact task bundle and its derived scoring contract, reward
policy, environment fingerprint, grader identity, harness commit, candidate identities,
and required run counts. For a repair task, the role matrix is:

| Role | Required runs | Required result |
|---|---:|---|
| original | at least two, exactly as planned | every strict stage passes |
| revert | one | the reference candidate passes and matches reference behavior |
| alternative | one per declared alternative | every strict stage passes |
| public mutant | one | ingest, compile, and object policy pass; verifier fails |
| negative control | one per declared control | reaches and fails its declared functional or semantic stage |

The plan must enumerate every alternative and negative control in the private task
projection. Candidate identities are content digest plus byte length, and identities may
repeat only where the original and revert deliberately use the same reference source.
Generation-family admission is not implemented in Phase 0.

## Verification rules

`bpe task admission verify` reconstructs the scoring contract from the task rather than
trusting a supplied contract. It then:

- rejects evidence whose task, environment, grader, or harness identity differs from the
  plan;
- requires microVM-shaped evidence and a microVM isolation fingerprint;
- deterministically rescores every evidence record and compares the full grade;
- checks that each carried replay manifest has the exact evidence, grade, scoring-contract,
  policy, candidate, and evidence-referenced artifact identities;
- checks that each replay anchor binds that manifest, evidence, grade, scoring contract, and
  policy;
- requires distinct request, episode, and replay-manifest identifiers and independent
  turn-zero requests;
- enforces the role matrix exactly, with no missing or extra attempts;
- requires repeated originals to have identical functional and semantic projections; and
- requires the revert projection to match the repeated-reference projection.

The resulting report binds the plan, task projections, contract, policy, environment,
grader, harness, ordered attempt set, reference behavior, and per-attempt digests. The
ordering is canonical, so reordering the input files does not change the report.

```bash
uv run bpe task admission verify tasks/my-task \
  runs/admission/*.json \
  --plan admission-plan.json \
  --policy policies/reward-v1.json
```

Once a report has been frozen, pass it back with `--report admission-report.json` to require
an exact deterministic match.

## What this does not prove

The current contract cannot establish any of the following:

- that an actual microVM executed the records rather than a producer constructing
  microVM-shaped JSON;
- that the carried replay manifests correspond to complete replay directories whose file
  bytes were independently verified;
- that an authenticated evaluator issued or externally anchored the receipts;
- that each run restored a distinct fresh snapshot instance—the environment schema binds
  the base snapshot digest, not a per-run instance identifier;
- that a stored AST edit and its inverse caused the mutant failure and revert success; or
- that hidden witness classes and every anti-hack obligation have a typed, independently
  reviewed kill matrix beyond the checks declared by the task.

Authoritative admission therefore belongs to the pinned Linux worker milestone. It will
add worker-produced replay verification, per-run snapshot receipts, authenticated issuer
attestations, mutation/inverse-edit identity, and a typed witness/control matrix. Until
then, Phase 0 receipts are useful for hardening the contract and testing adversarial
fixtures, but they are not permission to publish a task as admitted.
