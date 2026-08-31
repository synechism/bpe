# Static corpus contamination gate

Evaluation contamination invalidates the main project claim. BPE therefore treats corpus
identity, provenance, split assignment, and static similarity results as frozen artifacts,
not an informal preprocessing log.

The current detector is conservative and fail-closed. Its output field is named
`static_audit_passed`; it intentionally has no `clean`, `safe`, or `training_ready` field.

## Inputs

A candidate corpus and a separately rooted benchmark each use a
`bpe.corpus-manifest.v1` file. Every source entry binds:

- a unique source ID and normalized relative path;
- SHA-256 digest and byte length;
- split, contamination group, lineage group, and clone group; and
- repository, exact 40-character commit, upstream path, and license provenance.

The loader accepts only regular, non-symlink files beneath an exactly closed directory
tree. Unlisted files or directories, path traversal, duplicate JSON keys, nonfinite
numbers, invalid UTF-8 C, size-limit violations, and digest mismatches stop the audit.

The frozen v1 policy hard-denies the `cilium`, `xdp-tools`, and `bpftime` repository
families from the training split. These are defense-in-depth exclusions for the known
benchmark source families; normalizing a repository locator does not make its claimed
provenance trustworthy.

## Blocking checks

The detector checks all sources for duplicate IDs, exact content digests, and normalized C
token-sequence duplicates. It blocks any contamination, lineage, clone, or normalized
repository family shared between training and an evaluation-like split.

For fuzzy detection, it strips C comments and formatting, tokenizes deterministically, and
compares sets of fixed-size token n-grams. Every training source is compared against every
source in the development, calibration, validation, sealed-evaluation, and separate
benchmark splits. Either the frozen Jaccard or containment threshold is sufficient to
block. A tokenization error, source below the minimum token count, or missing pairwise
comparison is also blocking; skipped work cannot produce a pass.

Run and freeze an audit with:

```bash
uv run bpe corpus audit corpus/corpus-manifest.json \
  --benchmark benchmark/corpus-manifest.json \
  --policy policies/corpus-audit-v1.json \
  > corpus-audit-report.json
```

Recompute and compare a frozen report with:

```bash
uv run bpe corpus verify corpus-audit-report.json \
  --manifest corpus/corpus-manifest.json \
  --benchmark benchmark/corpus-manifest.json \
  --policy policies/corpus-audit-v1.json
```

Both commands exit nonzero for a blocking report. `verify` additionally rejects any report
that differs from a fresh deterministic audit of the exact manifests and policy.
The repository policy is also shipped byte-for-byte in the wheel as
`bpe/data/corpus-audit-v1.json`; callers still pass an explicit policy path so the selected
policy remains visible at the command boundary.

## Interpretation and limitations

A pass means only that this detector completed every declared static comparison without a
hit, skip, or error. It cannot prove the absence of:

- forks, mirrors, or vendored copies whose repository name and declared lineage changed;
- systematic identifier renaming, control-flow rewriting, semantic clones, or AST-level
  transformations;
- false provenance, incomplete clone groups, or an inaccurate license declaration;
- benchmark material acquired outside the frozen source trees; or
- contamination in model pretraining or another upstream dataset.

Before a corpus is training-ready, Phase 2 still needs independently collected provenance,
fork and vendoring analysis, calibrated structural/AST clone detection on disjoint data,
and manual review of every hit. Detector thresholds must be tuned on calibration sources,
validated once on different repositories and program families, then versioned and frozen;
they must not be adjusted after looking at sealed evaluation results.
