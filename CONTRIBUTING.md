# Contributing

Run `make check` before submitting changes. Changes to a Pydantic model must regenerate and
commit `schemas/`. Changes to scoring require a new policy or grader version plus replay and
adversarial-anchor tests; never silently edit a published policy in place.

Do not add training tasks without provenance, license, repository-family split, a working
reference, an alternative valid fix, behavior cases, semantic obligations, and the four
mandatory adversarial controls. A static lint pass is not authoritative admission.

Do not add training corpus content outside a closed `bpe.corpus-manifest.v1` tree. Preserve
the exact upstream commit, path, license, lineage, clone, and contamination-group metadata;
run the frozen corpus policy against every development, calibration, validation,
sealed-evaluation, and benchmark source. A passing static report is necessary but is not a
training-readiness claim.

Treat the worker wire format as a hostile-input boundary. The v1 request remains
capability-only and its execution/official fields remain literal `false`; candidate
transport or execution requires a new versioned schema, bounded content-addressed artifact
contract, subprocess/vsock adversarial tests, and an explicit trust review.
