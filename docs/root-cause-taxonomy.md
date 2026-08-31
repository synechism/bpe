# Repair root-cause taxonomy

Mutation suites use these stable IDs for the 12 bpfix-derived repair categories in the
project specification. A frozen repair suite declares the categories it covers and must
contain at least one task for each declared ID.

| Stable ID | Root cause | Seed mutation family |
|---|---|---|
| `unclamped_scalar` | Unclamped scalar used as an offset or length | remove range clamp |
| `stale_dynptr` | Corrupted or stale dynptr object | break dynptr lifetime/state |
| `packet_bounds` | Packet access lacks a bound on every path | remove packet-end guard |
| `missing_null_check` | Missing null check after a nullable helper | drop map-value guard |
| `pointer_provenance` | Pointer type or provenance mismatch | obscure or change pointer type |
| `unverified_address` | Unverified address dereferenced | replace tracked pointer with scalar address |
| `index_capacity` | Index exceeds object capacity | widen or remove index bound |
| `context_contract` | Context or helper contract misuse | use an invalid context field/helper pairing |
| `unpaired_reference` | Resource reference is not released | remove matching release operation |
| `interrupt_flags` | Interrupt flags are not restored in order | reorder save/restore operations |
| `probe_abi` | Probe signature mismatches the ABI | mutate section or function signature |
| `stack_buffer` | Stack buffer is oversized or uninitialized | inflate or partially initialize a buffer |

These labels describe the proof failure, not a required source edit. Equivalent fixes
receive full credit if they satisfy the frozen behavioral and semantic contract.
