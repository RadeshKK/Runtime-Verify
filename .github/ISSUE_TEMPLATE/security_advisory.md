---
name: 🛡️ Security Vulnerability / Policy Bypass
about: Report a potential policy bypass, evasion technique, or security issue
title: '[SECURITY] '
labels: ['security', 'critical']
assignees: ''
---

> [!CAUTION]
> If this vulnerability can be exploited in production environments against sensitive infrastructure, please review our [Security Policy](file:///D:/runtime-verify/SECURITY.md) for encrypted private reporting disclosures.

**Vulnerability Type**
- [ ] Policy Bypass / Filter Evasion (e.g. path normalization, command parsing)
- [ ] Replay / Challenge Token Tampering
- [ ] IMDS / SSRF Gating Bypass
- [ ] Rogue Multi-Agent Privilege Escalation
- [ ] Unbounded Resource Exhaustion (DoS)
- [ ] Other

**Attack Vector / Proof of Concept**
Provide minimal reproducible actions or scripts demonstrating how the policy is bypassed or exploited:

```python
# Minimal PoC
```

**Proposed Mitigation**
Any suggested fixes or regex/canonicalization rules to eliminate the bypass.
