# Public repository boundary

The evaluator checkout is not safe to push to a public Git host. Its tracked history may
contain active reference implementations, hidden fixtures, adversarial controls, and other
grader-only material even when a current directory listing looks filtered. Deleting those
paths in a later commit does not remove them from history.

Public `main` is therefore a fresh-history source projection, not a branch or clone of the
evaluator repository. Publication starts from one reviewed evaluator commit and copies only
the source-distribution allowlist declared in `pyproject.toml`:

- the root packaging, license, contribution, security, and README files;
- `docs/`, `policies/`, `schemas/`, `scripts/`, `src/`, `suites/`, and `worker/`;
- each task's `public/` subtree; and
- the locked dependency file.

The projection excludes evaluator Git metadata, `.github/`, `tests/`, every task `grader/`
subtree, replay/runs output, build products, caches, and generated `PKG-INFO`. Internal tests
and CI are omitted because they exercise withheld task material and would create a
misleading or failing public checkout if copied without that material.

## Required publication gate

Every update must satisfy all of these conditions:

1. Commit and fully test the evaluator state on local `main`.
2. Regenerate schemas and build the sdist from the locked environment.
3. Verify the archive has one canonical root, regular files/directories only, no duplicate
   or unsafe paths, and an exact match to the tracked public allowlist.
4. Reject every path containing a task-private `grader` component and inspect the resulting
   content for credentials or hidden inputs.
5. Extract into a new temporary directory without any evaluator `.git` directory, remove
   generated package metadata, and compare its file set and bytes with the audited
   projection.
6. Create a new single-snapshot Git commit in that temporary directory. Never merge, fetch,
   graft, or force-push evaluator history into the public repository.
7. Confirm the expected public remote head immediately before a non-force update to `main`.

The public snapshot is documentation and installable source, not an authoritative evaluator.
It contains schemas and integrity mechanisms but no active hidden witnesses, reference
answers, sealed replay inputs, signing keys, or official-result authority.
