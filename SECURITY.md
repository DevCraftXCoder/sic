# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security vulnerabilities.

Contact via GitHub: [@DevCraftXCoder](https://github.com/DevCraftXCoder)

Response time: 72 hours for acknowledgment, 7 days for critical issues.

---

## Responsible Use

SIC is an **offensive security toolkit** designed exclusively for:

- Authorized penetration testing engagements
- CTF (Capture the Flag) competitions
- Security research in isolated lab environments
- Defensive use cases (understanding attacker tooling)

**Never use SIC against systems you do not own or have explicit written authorization to test.** Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in most jurisdictions.

---

## Security Architecture

### Scope Enforcement

The scope enforcer (`scope_enforcer.py`) is the primary safety gate:

- All scan targets are validated against an `ALLOWED_TARGETS` whitelist before execution
- Wildcard targets are rejected unless explicitly allowlisted with a CIDR notation
- Out-of-scope requests return an error and are logged — they never execute
- The whitelist is configured at startup and cannot be modified via API at runtime

### Container Isolation (Docker)

All tool execution happens inside a hardened Docker container:

| Control | Value | Purpose |
|---|---|---|
| Port binding | `127.0.0.1:9888` | Never reachable from the network |
| User | `scanner` (uid 1001) | Non-root, no privilege escalation |
| Capabilities | `cap_drop: ALL` | Zero Linux capabilities |
| Privilege escalation | `no-new-privileges: true` | Blocks setuid/setgid |
| CPU limit | 2 cores | Prevents resource exhaustion |
| Memory limit | 2 GB | Bounded resource usage |
| DNS | `127.0.0.1` only | Blocks external hostname resolution |
| Dry-run default | `DRY_RUN_DEFAULT=true` | Must explicitly opt into live scans |
| Scan timeout | 300s hard wall | Kills runaway scans |
| Volume mounts | `./output` only | Source code baked into image |

### API Authentication

- All API endpoints require a valid API key passed via the `X-API-Key` header
- API keys are generated at server startup and stored only in the local environment
- Zero network exposure: the API binds to `127.0.0.1` only — not reachable without local access

### Zero-Trust IP Allowlisting

Admin operations are locked behind IP allowlisting in addition to API key auth:

- Requests must originate from the configured home network CIDR
- VPN exits, proxies, and foreign IPs are rejected even with a valid key
- IPv6 prefix matching requires minimum /64 specificity to prevent broad-prefix bypass

### Dry-Run Mode (Default On)

All scans default to dry-run mode:

- Dry-run mode shows what *would* be executed without sending any packets
- Live scans require an explicit `dry_run: false` parameter per request
- This prevents accidental execution during API exploration or testing

### No Telemetry

- No usage data sent externally
- No scan results transmitted to third parties
- All output stays in the local `./output/` directory
- No callbacks, beacons, or phone-home behavior

---

## Dependency Security

- All Python dependencies pinned to specific version ranges in `requirements.txt`
- Heavy optional dependencies (angr, pwntools, mitmproxy) clearly separated from core deps
- `requirements-core.txt` provides a minimal Windows-compatible install for API server only
- Run `pip audit` periodically to check for vulnerable packages

---

## Known Limitations

- This framework executes real offensive security tools — misuse can cause real damage
- Scope enforcement is a defense-in-depth measure, not a substitute for operator judgment
- Docker container isolation does not protect against host kernel vulnerabilities
- AI-generated tool parameters should be reviewed before execution in production environments

---

## Compliance Notes

SIC is intended for security professionals operating within legal frameworks. Ensure you have:

- Written authorization from the system owner before any testing
- A defined scope document specifying in-scope and out-of-scope assets
- Proper engagement rules of engagement (RoE) agreed with the client
- Compliance with any applicable data protection regulations (GDPR, HIPAA, etc.) when handling scan results
