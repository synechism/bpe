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

After that archive is audited and extracted, publication adds one closed operational overlay
from the same reviewed commit:

- `.github/workflows/ci.yml`;
- `.github/workflows/native-qualification.yml`;
- `tests/integration/cgroup_v2_native_probe.py`; and
- `tests/integration/inert_fixture_launcher_native_probe.py`.

Those four paths are required for public CI to trigger and produce the replayable native
launcher qualification report. They are not included in the source distribution or wheel.
The ordinary workflow recognizes exactly two coherent layouts: the evaluator checkout has
the private smoke-task grader plus the complete unit and contract suites, while the public
projection has none of those paths and exactly the two allowlisted integration probes. A
partial or expanded tracked test projection fails CI, as does a symlink, gitlink, non-stage-0
entry, or non-regular Git mode under `tests/`.

The projection otherwise excludes evaluator Git metadata, all other `.github/` and `tests/`
paths, every task `grader/` subtree, replay/runs output, build products, caches, and generated
`PKG-INFO`. The internal suite is omitted because it exercises withheld task material and
would create a misleading or failing public checkout if copied without that material.

## Required publication gate

Every update must satisfy all of these conditions:

1. Commit and fully test the evaluator state on local `main`.
2. Regenerate schemas and build the sdist from the locked environment.
3. Verify the archive has one canonical root, regular files/directories only, no duplicate
   or unsafe paths, and an exact match to the tracked public allowlist.
4. Reject every path containing a task-private `grader` component and inspect the resulting
   content for credentials or hidden inputs.
5. Extract into a new temporary directory without any evaluator `.git` directory, remove
   generated package metadata, and compare its file set and bytes with the audited source
   projection.
6. Copy only the four operational-overlay files listed above from exact blobs in the same
   reviewed commit. Verify their bytes, reject every Git path outside the source-distribution
   allowlist plus those four files, and confirm that every critical source path named by
   native qualification is present.
7. Create a new single-snapshot Git commit in that temporary directory. Never merge, fetch,
   graft, or force-push evaluator history into the public repository.
8. Confirm the expected public remote head immediately before a non-force update to `main`.

The public snapshot is documentation and installable source, not an authoritative evaluator.
It contains schemas and integrity mechanisms but no active hidden witnesses, reference
answers, sealed replay inputs, signing keys, or official-result authority.
