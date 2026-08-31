# Typed XDP oracle

The v1 XDP oracle is a pure comparison layer. It does not load or execute eBPF. A future
trusted runner emits one raw `bpe.xdp-trace.v1` record for the candidate and one for the
reference; `derive_oracle_report` deterministically produces `bpe.oracle-report.v1` under a
frozen `bpe.xdp-oracle-contract.v1` contract.

The contract closes the functional vocabulary to seven assertion kinds: return value,
packet bytes, context bytes, map snapshot, map delta, ordered events, and persistent
counters. Every case binds the exact content identity of its stored input fixture and fixes
the driver to one `bpf_prog_run/xdp@1` invocation. Candidate and reference traces must have
the same task, plan, grader, environment, harness, case order, and input identities. Missing,
extra, reordered, or type-mismatched observations fail before comparison.

Normalization is opt-in and closed. V1 permits only byte-range masking, declared against a
specific assertion and a type-compatible component. Rules are canonical, disjoint, bounded,
and part of the oracle-contract hash together with the normalizer version and implementation
digest. Map deltas are derived from normalized before/after snapshots; event order is never
sorted away. A supplied report is accepted only when it exactly equals a fresh deterministic
derivation, which also rejects normalization claims not present in the contract.

An oracle report retains the normalized candidate and reference projections, per-assertion
hashes and matches, and the first required divergence in contract order. Strict functional
success is the conjunction of all required assertions; optional mismatches remain visible but
do not redefine that gate.

Replay v2 should content-address the oracle contract, both raw traces, and the report, then
cross-bind the candidate program digest to the evaluation request, the reference digest and
case fixtures to the sealed evaluation plan, and the environment/normalizer/harness fields to
the grader identity. Verification should call `verify_oracle_report` rather than trusting
worker-supplied match booleans or deltas.
