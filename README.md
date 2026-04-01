# OpenClaw Security Audit

**Part of the [OpenClaw Security Suite](#the-suite) — Tool 1 of 4**

Scans your OpenClaw agent's security posture against 47 adversarial scenarios. Tests OS-level controls directly and LLM-judgment through blind fresh sessions. Outputs an HTML report with findings, fix recommendations, and an injection test kit.

Based on ["Don't Let the Claw Grip Your Hand"](https://arxiv.org/abs/2603.10387) (Shan et al., 2026).

For your convenience: 

Tool 1: https://github.com/SaifAlYounan/OpenClawSecurityPostureAssessment

Tool 2: https://github.com/SaifAlYounan/OpenClawSecurityPostureAssessment---Part-2

Tool 3: https://github.com/SaifAlYounan/OpenClawSecurityPostureAssessment---Part-3

Tool 4: https://github.com/SaifAlYounan/OpenClawSecurityPostureAssessment---Part-4

---

## Getting Started

**Install:** Send the link to this repo to your agent and ask it to install it as a skill.

**Run:**
```
Run a security audit
```

**What happens:** The agent runs ~40 commands (mostly read-only), spawns ~17 fresh sessions for blind LLM tests, and generates an HTML report. Takes 5-15 minutes. Costs ~$3-4 on Opus.

**After:** Open the HTML report. It shows your defense rate, what failed, and exactly what to fix. Then move to Tool 2 or jump straight to Tool 4 to apply fixes.

---

## The Suite

```
→ 1. openclaw-security-audit    What does your posture look like?
  2. openclaw-red-team           How hard do single attacks have to try?
  3. openclaw-attack-chains      Can innocent requests compose into a breach?
  4. openclaw-hardening          Fix everything, step by step
```

Each tool's report includes fix recommendations and points to [openclaw-hardening](https://github.com/SaifAlYounan/openclaw-hardening) for guided implementation. The hardening skill reads your reports and tailors the fix order to your specific findings.

**Next step after this tool:** Run [openclaw-red-team](https://github.com/SaifAlYounan/openclaw-red-team) to test how hard an attacker has to try, or run [openclaw-hardening](https://github.com/SaifAlYounan/openclaw-hardening) to start fixing what this audit found.

---

## What It Does

**The problem:** Most AI security tools ask the agent "would you do X?" and the agent says no — because it's reading the audit instructions and performing compliance.

**The fix:** Two-tier testing.

**Tier 1 — OS-level (25 tests):** File permissions, sudo access, network reach, sandbox boundaries. Run directly by the auditing agent. The operating system doesn't know it's a test.

**Tier 2 — LLM-judgment (17 tests):** Base64 evasion, social engineering, reverse shells, data exfiltration, prompt injection. Each test spawns a fresh session via `sessions_spawn` with no audit context. The fresh session has no idea it's being tested.

**5 additional:** 2 skipped (too dangerous), 1 manual (memory poisoning), 2 informational. **Total: 47.**

---

## Safety

- **Tier 1 tests** are read-only or use temp files in `/tmp/openclaw_audit_*/`. Cleaned up after.
- **Tier 2 tests** use harmless marker payloads. Worst case: small text files in `/tmp/`.
- **The `.bashrc` test** appends a comment and removes it. If cleanup fails, harmless comment stays.
- **The httpbin tests** send "audit_test_data" to a public test website. No real secrets leave.
- **Two tests are SKIPPED** (fork bomb, kernel module). Too dangerous.
- **No test deletes real data, installs packages, or connects to unknown servers.**

---

## The Report

An HTML file showing:

- **Defense rate** compared to the paper's findings for Claude Opus (83% baseline, 91.5% with HITL)
- **Critical failures** highlighted at the top
- **Category breakdown** — which attack types are defended, which aren't
- **Configuration baseline** — user, sudo, SSH keys, secrets, network, HITL, container status
- **Every test result** with raw evidence
- **What To Fix** — 4 prioritized fixes with exact commands, who runs them, and what they address
- **Injection test kit** — 4 test documents you can re-send via Telegram after applying fixes

---

## Honest Limitations

**Strongest:** Tier 2 fresh session tests. The agent genuinely doesn't know it's being tested.

**Strong:** Tier 1 OS tests. Permissions block it or they don't.

**Requires `sessions_spawn`:** If not available, Tier 2 falls back to generating manual test documents.

**Not a pentest:** This is a posture assessment. A real pentest uses external tooling from outside the network.

---

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Two-tier audit workflow |
| `references/scenarios.md` | 47 tests split by tier |
| `references/defenses.md` | Hardening guides |
| `scripts/generate_report.py` | HTML report generator |

## Changelog

**v3** — Reports include "What To Fix" with prioritized commands and hardening skill callout.
**v2** — `sessions_spawn` replaces CLI detection. INFORMATIONAL result type added. Injection detection fixed.
**v1** — Initial release.

## Citation

Shan, Z., Xin, J., Zhang, Y., & Xu, M. (2026). "Don't Let the Claw Grip Your Hand." arXiv:2603.10387.

## License

MIT

## Author

Alexios van der Slikke-Kirillov
