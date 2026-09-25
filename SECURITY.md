# Security Policy

RuntimeVerify takes the security of autonomous AI agent infrastructure seriously. We appreciate the efforts of security researchers and engineers in keeping our project and users safe.

---

## Supported Versions

Security updates and vulnerability patches are actively provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or potential bypass in RuntimeVerify, **please do not create a public GitHub issue.** Public disclosure exposes users before a fix can be prepared and distributed.

### Private Disclosure Channels

Please report vulnerabilities using one of the following methods:

1. **GitHub Security Advisory**: Submit a private report via the **Security** tab -> **Advisories** -> **Report a vulnerability** on GitHub.
2. **Security Team Email**: Send a detailed advisory to `security@runtimeverify.dev`.

### Report Contents

To help us investigate and triage your report quickly, please include:

- **Component Affected**: CLI, API, SDK, Policy Engine, Interceptor, Audit, or Dashboard.
- **Vulnerability Category**: E.g., Policy Bypass, SSRF, Command Injection Evasion, Path Traversal, Credential Leakage, or Approval Replay.
- **Description & Impact**: A clear description of the issue and potential consequences.
- **Proof of Concept (PoC)**: Minimal reproducible steps, code snippets, sample payloads, or scripts demonstrating the issue.
- **Proposed Remediation**: Any suggested fixes or mitigation recommendations (optional).

---

## Response Process & SLAs

Our security response team commits to the following timeline:

- **Initial Acknowledgment**: Within **48 hours** of receiving your report.
- **Triage & Severity Assessment**: Within **5 business days**, confirming whether the issue is reproducible and determining its CVSS score.
- **Remediation & Patch Development**: A fix will be developed in a private branch, with target resolution within **30 calendar days** for Critical/High severity issues.
- **Release & Public Credit**: A patched release will be published alongside a security advisory, crediting the reporter (unless anonymity is requested).

---

## Responsible Disclosure Guidelines

We ask that researchers:

- Allow reasonable time for remediation before publishing or sharing vulnerability details publicly.
- Do not access, modify, or exfiltrate private user or customer data during research.
- Do not perform denial-of-service attacks or disrupt production systems.
- Test only against locally hosted or dedicated development instances of RuntimeVerify.

---

## Operational Scope & Architectural Boundaries

Please review [`docs/security/threat-model.md`](docs/security/threat-model.md) and [`docs/security/security-model.md`](docs/security/security-model.md) prior to submitting reports.

RuntimeVerify is an **application-layer verification and interception engine**, not an operating system kernel sandbox. Reports alleging that an agent process with unconstrained root access can terminate parent processes outside the interceptor are considered out of scope, as kernel isolation must be provided by container or microVM runtimes.
