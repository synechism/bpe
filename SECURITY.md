# Security policy

BPE evaluates adversarial source intended for a privileged Linux subsystem. Until the
microVM worker is complete and audited, do not load untrusted candidate BPF on a workstation,
production host, shared CI runner, or long-lived kernel.

Official benchmark execution will require a disposable pinned microVM. Native Linux support
is development-only and synthetic/recorded evidence is ineligible for official scores.
Privileged self-hosted verifier jobs must never run on untrusted pull requests.

Report a vulnerability privately through GitHub's security-advisory interface for this
repository. Include the affected contract version, a minimal replay/task bundle where safe,
and whether the issue can escape the compiler sandbox or verifier guest, forge replay
integrity, leak private grader assets, or award false benchmark success.
