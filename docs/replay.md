# Replay format

Each attempt produces a write-once-by-contract, content-addressed directory:

```text
run/
├── manifest.json
├── events.jsonl
├── evidence.json
├── contract.json
├── grade.json
├── policy.json
└── artifacts/sha256/<digest>
```

`manifest.json` hashes every top-level record and every binary artifact, including the
submitted candidate. Evidence contains only stage facts and artifact references; it never
trusts a scalar score returned by a worker. `contract.json` freezes the exact required
check manifest. `grade.json` is reproduced by applying `policy.json` and `contract.json`
to `evidence.json`.

`bpe replay verify RUN` checks the closed directory tree, canonical records, file type,
byte length, SHA-256, every evidence-to-artifact reference, canonically derived events,
and deterministic rescoring. Any missing, extra, corrupt, or symlinked record or artifact
fails closed. `bpe replay rescore RUN --policy NEW.json` changes only the derived grade; it
never executes candidate code.

These checks establish internal integrity, not authenticity. Someone who controls the
directory can replace the candidate, evidence, grade, and manifest together and compute
new matching hashes. A verifier therefore reports two distinct properties:

- **valid**: the replay is internally complete, canonical, content-addressed, and
  deterministically rescored; and
- **anchored**: the manifest digest also matches an expected digest obtained independently
  from a trusted evaluator registry or attestation.

Callers asking for strict anchored aggregation must supply that external expected manifest
digest. A canonical registry additionally binds each manifest to the exact evidence, grade,
scoring-contract, and reward-policy digests and to the precommitted experiment. The registry
digest must itself come from an independent append-only or signed channel; a digest copied
from the replay is not an external anchor.

Phase 0 treats even a matching external digest as an integrity/provenance check, not as
authority. Its capability-only worker has not run the candidate on the pinned kernel, and
the registry schema does not authenticate an evaluator issuer. Consequently every Phase 0
benchmark report has `official: false`; authoritative attestation is a worker milestone.

A future authoritative runner will not require timing and raw verifier-log prose to replay
byte-for-byte across a rerun. It will require canonical functional outputs, assertion results,
stage classifications, grader identity, and strict score to match. It will store or
content-address exact hidden inputs rather than regenerate them from an undocumented PRNG;
replay v1 does not itself establish that runner-side input closure.

Sealed-evaluation replay blobs contain hidden inputs and therefore remain encrypted or
access-controlled by the evaluator while the split is active. Only the allowed diagnostic
projection reaches the model. Registry attestations may be public; full blobs are released
only after the split is retired or its secrecy is no longer required.
