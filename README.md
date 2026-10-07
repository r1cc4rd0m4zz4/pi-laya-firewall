# pi-laya-firewall

**Agent Application Firewall (AAF) & Deterministic Taint DAG for [Pi Coding Agent](https://github.com/earendil-works/pi).**

Powered by local, air-gapped neural policy models via upstream [`laya`](https://github.com/NandhaKishorM/laya) running on loopback (`http://127.0.0.1:5292`).

---

## Architecture & Defense-in-Depth

1. **Deterministic Taint DAG & Integrity Paths**: In-process tracking of credentials and sensitive targets (`~/.ssh`, `~/.aws`, `.env`). Separate Integrity Path protection for agent extensions (`~/.pi/agent`) blocking unauthorized code mutation while allowing 0ms reads. Transitive taint propagates across file copy (`cp`, `mv`), redirection (`cat > dst`), pipe-to-tee (`| tee`), and archives (`tar`, `zip`).
2. **Sub-Millisecond Hard Heuristics (<0.05ms)**: Drops shellcode, reverse shells, piping curl-to-shell, and multi-format cloud IMDS SSRF probes (decimal, hex, IPv6, GCP, Alibaba) prior to execution.
3. **Audit Log Immutability (Zero-Tampering)**: Hard blocks any agent or sub-agent from deleting (`rm`), truncating (`>`), or modifying `firewall.jsonl` or `warden.jsonl` audit records (*Auditor != Audited*).
4. **Safe Local Git Fast-Path & Anti-Cheating**: 0ms execution for local, non-push, non-force Git operations. Strictly rejects lazy/evasive commit messages (`update`, `fix`, `wip`, or <10 chars) while requiring descriptive conventional commits.
5. **Local Laya System 1 Inference**:
   - Evaluates positive security queries: `is_safe_operation`, `no_secret_egress`, `is_aligned_with_goal`.
   - Stephen Hawking Min-Pooling ($\min(P)$) over bounded holographic windows (Head/Mid/Tail) to prevent poisoned chunk dilution.
   - Deterministic model triage: ModernBERT for English, multilingual mmBERT for Italian, typed-decisions for code mutations and taint.
6. **Transparent Auto-Wake-on-Demand**: When the background inference service is in auto-hibernation (consuming 0.0 MB RAM), the firewall wakes it up automatically in 2-3 seconds on the first tool call without interrupting workflow.
7. **Post-Execution DLP Sanitization**: Redacts private keys, AWS tokens, GitHub credentials, and Slack secrets before output reaches the agent transcript.
8. **Fail-Closed & Forced Choice**: If the local inference daemon is unreachable and cannot be woken, execution halts. Human confirmation dialogs default strictly to **NO** on Enter.

---

## Prerequisites

Start the local `laya-serve` daemon on `127.0.0.1:5292`. We recommend managing it via [`laya-ctl`](https://github.com/r1cc4rd0m4zz4/laya-ctl):

```bash
# Install and start the laya daemon
laya-ctl setup
laya-ctl start
```

---

## Installation

Install directly into Pi via Git:

```bash
pi install git:github.com/r1cc4rd0m4zz4/pi-laya-firewall
```

Or link locally:

```bash
pi install /path/to/pi-laya-firewall
```

---

## Interactive Slash Commands

- `/laya status`: Connection health to `127.0.0.1:5292`, device status (MPS/CUDA/CPU), active models, and tracked taint paths.
- `/laya logs`: Displays the last 5 firewall audit events for the current session.
- `/laya s1 <prompt>`: Interactive System 1 positive policy classification test.

Audit logs are persisted in `~/.cache/laya/firewall.jsonl`.

---

## Verification & Testing

Run the 37-invariant antagonistic regression suite (stdlib Python):

```bash
npm test
# or
python3 tests/test_regression.py
```

---

## License

MIT
