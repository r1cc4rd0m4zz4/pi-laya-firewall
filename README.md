# pi-laya-firewall

**Agent Application Firewall (AAF) & Deterministic Taint DAG for [Pi Coding Agent](https://github.com/earendil-works/pi).**

Powered by local, air-gapped neural policy models via upstream [`laya`](https://github.com/NandhaKishorM/laya) running on loopback (`http://127.0.0.1:5292`).

---

## Architecture & Defense-in-Depth

1. **Deterministic Taint DAG & Multi-Step Staging Resilience**: In-process tracking of credentials and sensitive targets (`~/.ssh`, `~/.aws`, `.env`). Separate Integrity Path protection for agent extensions (`~/.pi/agent`) blocking unauthorized code mutation while allowing 0ms reads. Transitive taint propagates across file copy (`cp`, `mv`), stream transformations (`awk`, `sed`, `tr`, `base64`), input/output redirection (`> dst`, `< src`), pipe-to-tee (`| tee`), and archives (`tar`, `zip`, `7z`) across separate tool calls and prompt turns.
2. **Sub-Millisecond Hard Heuristics (<0.05ms)**: Drops shellcode, reverse shells, piping curl-to-shell, and multi-format cloud IMDS SSRF probes (decimal, hex, IPv6, GCP, Alibaba) prior to execution.
3. **Chained Pipeline Atomicity Engine**: Decomposes compound shell pipelines (`&&`, `||`, `;`, `&`, `\n`) into atomic execution units. Enforces invariants atom-by-atom, preventing attackers from smuggling unauthorized commits or exfiltration inside benign local command chains.
4. **Hawking Conservation Law for Clean Local Workspace**: Clean local development operations (TDD test execution, builds, linters, passive shell queries) with zero taint and zero network egress flow freely in 0ms without neural overblocking.
5. **Kernel-Level Audit Log Immutability**: Native OS append-only flags (`chflags uappnd` on macOS) protect `firewall.jsonl` and `warden.jsonl` audit records against deletion (`rm`), truncation (`>`), or tampering without requiring root/sudo (*Auditor != Audited*).
6. **Intent-Gated Local Git & Pre-Commit DLP**: 0ms execution for local Git operations; autonomous agent commits are blocked unless the user explicitly requested them in the prompt, guarded by pre-commit DLP diff scanning and rejection of `--no-verify`.
7. **Local Laya System 1 Inference & Holographic Security Tensor**:
   - `convaiinnovations/laya-typed-decisions` (421M ModernBERT-large) evaluates a multi-dimensional security tensor in a single ~25ms forward pass: orthogonal multi-class `intent_classification` (`choice`), ordinal `blast_radius` (`score`), and calibrated `no_secret_egress` (`noul`) using detailed semantic criteria.
   - Fast ModernBERT-base for routine CLI commands; multilingual mmBERT for Italian.
   - Stephen Hawking Min-Pooling ($\min(P)$) over bounded holographic windows (Head/Mid/Tail) to prevent poisoned chunk dilution.
8. **Transparent Auto-Wake-on-Demand**: When the background inference service is in auto-hibernation (consuming 0.0 MB RAM), the firewall wakes it up automatically in 2-3 seconds on the first tool call without interrupting workflow.
9. **Post-Execution DLP Sanitization**: Redacts private keys, AWS tokens, GitHub credentials, and Slack secrets before output reaches the agent transcript.
10. **Fail-Closed & Forced Choice**: If the local inference daemon is unreachable and cannot be woken, execution halts. Human confirmation dialogs default strictly to **NO** on Enter.

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

Run the 42-invariant antagonistic regression suite (stdlib Python):

```bash
npm test
# or
python3 tests/test_regression.py
```

---

## License

MIT
