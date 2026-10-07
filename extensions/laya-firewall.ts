import * as cp from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const LAYA_SERVER_URL = process.env.LAYA_SERVER_URL || "http://127.0.0.1:5292";
const CONFIRM_TIMEOUT_MS = Number.parseInt(process.env.LAYA_CONFIRM_TIMEOUT_SEC || "300", 10) * 1000;
const SAFE_READONLY_TOOLS = new Set(["read", "grep", "find", "ls"]);
const LOG_FILE = path.join(os.homedir(), ".cache/laya/firewall.jsonl");

interface LayaDecision {
  requires_human_confirmation: boolean;
  verdict: "ALLOW" | "REQUIRE_CONFIRMATION" | "BLOCK";
  risk_score: number;
  is_tainted: boolean;
  reason: string;
  hard_block?: boolean;
}

function getSessionId(ctx: any): string {
  if (process.env.PI_SESSION_ID) return process.env.PI_SESSION_ID;
  const file = ctx?.sessionManager?.getSessionFile?.();
  if (file) return path.basename(file, ".jsonl");
  return "session-" + process.pid;
}

function logFirewallEvent(sessionId: string, event: string, target: string, details: Record<string, unknown>): void {
  try {
    const entry = JSON.stringify({
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      cwd: process.cwd(),
      component: "laya-firewall",
      event,
      target,
      details,
    }) + "\n";
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true, mode: 0o700 });
    fs.appendFileSync(LOG_FILE, entry, "utf-8");
    if (process.platform === "darwin") {
      try { cp.execFileSync("chflags", ["uappnd", LOG_FILE], { stdio: "ignore" }); } catch {}
    }
  } catch {
    // Non-blocking on log write failure
  }
}

// -----------------------------------------------------------------------------
// 1. In-Process Deterministic Taint Tracking DAG
// -----------------------------------------------------------------------------
class InProcessTaintTracker {
  private taintedPaths: Set<string> = new Set();
  public version = 1;

  private defaultSeeds = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "~/.netrc",
    "~/.kube",
    "~/.bash_history",
    "~/.zsh_history",
    "~/.zshrc",
    "~/.bashrc",
    "~/.zprofile",
    "~/.profile",
    "~/.gitconfig",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/master.passwd",
  ];

  private integritySeeds = [
    "~/.pi/agent",
  ];
  private integrityPaths: Set<string> = new Set();

  private sensitivePatterns = [
    /(?:^|[\/\\])\.env(?:\..+)?$/i,
    /\.(?:pem|key|pkcs12|pfx)$/i,
    /id_(?:rsa|ed25519|ecdsa|dsa)$/i,
    /(?:credentials|secrets?\.json|token.*\.json)$/i,
    /(?:.*dump.*\.sql|.*backup.*\.sql|.*\.sqlite3?)$/i,
  ];

  constructor() {
    for (const seed of this.defaultSeeds) {
      const canon = this.canonicalize(seed);
      if (canon) this.taintedPaths.add(canon);
    }
    for (const seed of this.integritySeeds) {
      const canon = this.canonicalize(seed);
      if (canon) this.integrityPaths.add(canon);
    }
  }

  isPathIntegrityProtected(pathStr: string, cwd?: string): boolean {
    const canon = this.canonicalize(pathStr, cwd);
    if (!canon) return false;
    for (const p of this.integrityPaths) {
      if (canon === p || canon.startsWith(p + path.sep)) {
        return true;
      }
    }
    return false;
  }

  canonicalize(pathStr: string, cwd?: string): string | null {
    if (!pathStr || typeof pathStr !== "string") return null;
    try {
      let clean = pathStr.trim().replace(/^@+/, "");
      if (clean.startsWith("~")) {
        clean = path.join(os.homedir(), clean.slice(1));
      }
      if (!path.isAbsolute(clean) && cwd) {
        clean = path.resolve(cwd, clean);
      } else if (!path.isAbsolute(clean)) {
        clean = path.resolve(process.cwd(), clean);
      }
      try {
        return fs.realpathSync(clean);
      } catch {
        return path.resolve(clean);
      }
    } catch {
      return null;
    }
  }

  isPathSensitive(pathStr: string, cwd?: string): boolean {
    if (!pathStr) return false;
    const canon = this.canonicalize(pathStr, cwd);
    if (!canon) return false;

    for (const tainted of this.taintedPaths) {
      if (canon === tainted || canon.startsWith(tainted + path.sep)) {
        return true;
      }
    }

    const baseName = path.basename(canon);
    for (const pat of this.sensitivePatterns) {
      if (pat.test(baseName) || pat.test(canon)) {
        return true;
      }
    }
    return false;
  }

  markTainted(pathStr: string, cwd?: string): void {
    const canon = this.canonicalize(pathStr, cwd);
    if (canon && !this.taintedPaths.has(canon)) {
      this.taintedPaths.add(canon);
      this.version += 1;
    }
  }

  inspectAndPropagateBash(command: string, cwd?: string): void {
    if (!command) return;

    // Detect destination sinks: redirection (> dst), tee (| tee dst), archives (tar/zip/7z dst), copy/move (cp/mv dst)
    let dst: string | null = null;
    const teeMatch = command.match(/\|\s*(?:sudo\s+)?tee\s+(?:-[a-zA-Z]+\s+)*([^\s|;&]+)/i);
    const redirMatch = command.match(/>>?\s*([^\s|;&]+)/);
    const archMatch = command.match(/\b(?:tar\s+-[a-zA-Z0-9]*f|zip\s+(?:--?[a-zA-Z0-9_=-]+\s+)*|7z\s+a\s+)\s*([^\s]+)/i);
    const cpMatch = command.match(/\b(?:cp|mv|rsync|Copy-Item|Move-Item|install)\s+(?:-[a-zA-Z0-9]+\s+)*([^\s]+)\s+([^\s]+)/i);

    if (teeMatch && teeMatch[1]) {
      dst = teeMatch[1].replace(/['"]/g, "");
    } else if (redirMatch && redirMatch[1]) {
      dst = redirMatch[1].replace(/['"]/g, "");
    } else if (archMatch && archMatch[1]) {
      dst = archMatch[1].replace(/['"]/g, "");
    } else if (cpMatch && cpMatch[1] && cpMatch[2]) {
      const src = cpMatch[1].replace(/['"]/g, "");
      const target = cpMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(target, cwd);
      }
      return;
    }

    if (dst && !dst.startsWith("/dev/null") && !dst.startsWith("/dev/zero")) {
      const tokens = command.match(/[^@'"=<>|;&()\s]+/g) || [];
      for (const tok of tokens) {
        if (tok !== dst && this.isPathSensitive(tok, cwd)) {
          this.markTainted(dst, cwd);
          return;
        }
      }
    }
  }

  isCommandTainted(command: string, cwd?: string): boolean {
    if (!command) return false;
    for (const tainted of this.taintedPaths) {
      if (command.includes(tainted)) return true;
      const home = os.homedir();
      if (tainted.startsWith(home)) {
        const tildePath = "~" + tainted.slice(home.length);
        if (command.includes(tildePath)) return true;
      }
    }
    const tokens = command.match(/[^@'"=<>|;&()\s]+/g) || [];
    return tokens.some((tok) => this.isPathSensitive(tok, cwd));
  }

  getTaintCount(): number {
    return this.taintedPaths.size;
  }
}

const taintTracker = new InProcessTaintTracker();

// -----------------------------------------------------------------------------
// 2. Hard Security Heuristics (<0.05ms)
// -----------------------------------------------------------------------------
const SSRF_PATTERNS: [RegExp, string][] = [
  [/(?:169\.254\.169\.254|2852039166|0xa9\.?0xfe\.?0xa9\.?0xfe|0xa9fea9fe|0251\.0376\.0251\.0376|\[fd00:ec2::254\])/i, "Cloud IMDS Metadata endpoint access (SSRF / API7:2023)"],
  [/metadata\.google\.internal/i, "GCP Metadata endpoint access (SSRF / API7:2023)"],
  [/(?:100\.100\.100\.200|1678377416|0x64\.?0x64\.?0x64\.?0xc8)/i, "Alibaba Cloud Metadata access (SSRF / API7:2023)"],
  [/Metadata-Flavor:\s*Google/i, "GCP Metadata header probe (SSRF / API7:2023)"],
];

const SHELL_PATTERNS: [RegExp, string][] = [
  [/base64\s+(?:-d|--decode)/i, "Base64 decode in shell"],
  [/(?:openssl\s+enc\s+-d\s+-base64|xxd\s+-r)/i, "Alternative binary payload decoding"],
  [/\beval\s+/i, "Dynamic eval execution"],
  [/\b(?:sh|bash|zsh|dash)\s*<\(/i, "Process substitution execution"],
  [/curl\b.*\s*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python[23]?|node)/i, "Piped remote execution"],
  [/wget\b.*\s*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python[23]?|node)/i, "Piped remote execution"],
  [/(?:pty\.spawn\s*\(\s*['"][^'"]*sh['"]|os\.dup2\s*\([^,]+fileno\(\)|socket\.connect\b.*os\.dup2)/i, "Socket reverse shell execution"],
  [/\/dev\/tcp\/\d+/i, "Direct /dev/tcp socket connection"],
  [/\b(?:nc|ncat)\s+.*-e\b/i, "Netcat command execution flag"],
  [/python[23]?\s+-c\s+['"].*(?:pty|dup2\s*\(|socket\.connect\b|s\.connect\b)/i, "Inline Python reverse shell execution"],
  [/python[23]?\s+-c\s+['"].*(?:urllib\.request|requests|http\.client).*exec\s*\(/i, "Inline Python remote execution payload"],
  [/python[23]?\s+-m\s+(?:http\.server|SimpleHTTPServer)/i, "Unauthorized local HTTP file server exfiltration"],
  [/(?:DYLD_INSERT_LIBRARIES|LD_PRELOAD)\s*=/i, "Dynamic linker library injection hijack"],
  [/\brm\s+-[rR]*f\s+\/\s*$/i, "Destructive wipe of root filesystem"],
];

const INJECTION_PATTERNS: [RegExp, string][] = [
  [/ignore\s+(?:all\s+)?previous\s+instructions/i, "Prompt Injection override attempt (OWASP LLM01 / MCP04)"],
  [/disregard\s+(?:all\s+)?prior\s+guidelines/i, "Prompt Injection override attempt (OWASP LLM01 / MCP04)"],
  [/system\s+prompt\s+override/i, "System prompt extraction/override attempt (LLM07 / AST02)"],
];

function checkHardHeuristics(toolName: string, args: Record<string, unknown>): string | null {
  if (toolName in SAFE_READONLY_TOOLS) return null;

  if (toolName === "bash" || toolName === "fetch" || toolName.startsWith("mcp")) {
    const netTarget = `${String(args.command || "")} ${String(args.uri || "")} ${String(args.url || "")}`;
    for (const [re, desc] of SSRF_PATTERNS) {
      if (re.test(netTarget)) return `Hard security violation detected: ${desc}`;
    }
  }

  const queryTarget = `${String(args.command || "")} ${String(args.query || "")} ${String(args.prompt || "")}`;
  for (const [re, desc] of INJECTION_PATTERNS) {
    if (re.test(queryTarget)) return `Hard security violation detected: ${desc}`;
  }

  if (toolName === "bash") {
    const cmd = String(args.command || "");
    for (const [re, desc] of SHELL_PATTERNS) {
      if (re.test(cmd)) return `Hard security violation detected: ${desc}`;
    }
  }

  // Antagonistic Write / Edit Payload Inspection (MITRE T1059 / T1505 / CWE-94)
  if (toolName === "write" || toolName === "edit") {
    const p = String(args.path || args.file || "");
    if (/(?:\.cache[\/\\]laya[\/\\](?:firewall|warden)\.jsonl|laya_serve\.log)/i.test(p)) {
      return "Hard security violation: Unauthorized audit log overwrite attempt (Zero-Tampering / Controllore != Controllato)";
    }
    let payload = "";
    if (typeof args.content === "string") {
      payload = args.content;
    } else if (Array.isArray(args.edits)) {
      payload = (args.edits as { newText?: string }[]).map((e) => e.newText || "").join("\n");
    }

    if (payload) {
      for (const [re, desc] of SHELL_PATTERNS) {
        if (re.test(payload)) return `Hard security violation in file content: ${desc}`;
      }
      for (const [re, desc] of SSRF_PATTERNS) {
        if (re.test(payload)) return `Hard security violation in file content: ${desc}`;
      }
      for (const [re, desc] of INJECTION_PATTERNS) {
        if (re.test(payload)) return `Hard security violation in file content: ${desc}`;
      }
    }
  }

  return null;
}

// -----------------------------------------------------------------------------
// Stephen Hawking Bounded Horizon & Kevin Mitnick Anti-Evasion Engine
// -----------------------------------------------------------------------------
function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    freq[str[i]] = (freq[str[i]] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SUSPICIOUS_KEYWORDS = [
  /\b(?:eval|exec|os\.system|subprocess|shutil\.rmtree)\b/i,
  /\b(?:curl|wget|fetch|axios|urllib|http\.client)\b/i,
  /\b(?:base64|b64decode|atob|btoa|Buffer\.from)\b/i,
  /\b(?:BEGIN [A-Z ]*PRIVATE KEY|id_rsa|id_ed25519)\b/i,
  /\b(?:\/etc\/shadow|\/etc\/passwd|~\/\.ssh)\b/i,
];

function detectSuspiciousTokens(text: string): string[] {
  const found: string[] = [];
  for (const re of SUSPICIOUS_KEYWORDS) {
    const m = text.match(re);
    if (m) found.push(m[0]);
  }
  return found;
}

function boundStateHorizon(rawText: string, maxLimit = 1000): { bounded: string; highEntropy: boolean; suspiciousTokens: string[] } {
  const entropy = calculateShannonEntropy(rawText);
  const suspicious = detectSuspiciousTokens(rawText);

  if (!rawText || rawText.length <= maxLimit) {
    return {
      bounded: rawText || "",
      highEntropy: entropy > 5.4,
      suspiciousTokens: suspicious,
    };
  }

  // Mitnick noise stripping: collapse multi-line whitespace and padding
  const stripped = rawText.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n");
  const head = stripped.slice(0, 450);
  const tail = stripped.slice(-450);
  const horizon = `${head}\n... [HAWKING BOUNDED HORIZON: ${rawText.length} bytes, Entropy: ${entropy.toFixed(2)}] ...\n${tail}`;

  return {
    bounded: horizon,
    highEntropy: entropy > 5.2,
    suspiciousTokens: suspicious,
  };
}

function scrubSensitiveArgs(args: Record<string, unknown>): Record<string, unknown> {
  const scrubbed: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === "string") {
      scrubbed[k] = v.replace(/(?:-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9_]{36}|xox[baprs]-[0-9a-zA-Z]{10,48})/g, "[REDACTED_PRE_IPC]");
    } else {
      scrubbed[k] = v;
    }
  }
  return scrubbed;
}

function extractAstContext(toolName: string, input: Record<string, unknown>): string | null {
  const filePath = (input.path as string) || (input.file as string);
  if (!filePath) return null;

  const ext = path.extname(filePath).toLowerCase();
  const codeExts = new Set([".py", ".ts", ".js", ".tsx", ".jsx", ".rs", ".go", ".c", ".cpp", ".java"]);

  if (codeExts.has(ext)) {
    try {
      const astGrepBin = path.join(os.homedir(), ".local/bin/ast-grep");
      const out = cp.execFileSync(astGrepBin, ["outline", filePath], {
        timeout: 100,
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      if (out && out.trim()) return out.trim();
    } catch {
      // Diff fallback
    }
  }

  if (toolName === "edit" && Array.isArray(input.edits)) {
    return input.edits
      .slice(0, 5)
      .map((e: { newText?: string }) => `+ ${String(e.newText || "").slice(0, 120)}`)
      .join("\n") || null;
  }

  if (toolName === "write" && typeof input.content === "string") {
    return input.content.split("\n").slice(0, 8).join("\n").slice(0, 250) || null;
  }

  return null;
}

// -----------------------------------------------------------------------------
// 3. Upstream laya-serve HTTP Client (/v1/systemone)
// -----------------------------------------------------------------------------
const ITALIAN_MARKERS = new Set([
  "il", "lo", "la", "i", "gli", "le", "un", "uno", "una",
  "di", "a", "da", "in", "con", "su", "per", "tra", "fra",
  "che", "non", "sono", "e", "ed", "o", "od", "se", "ma",
  "questo", "questa", "questi", "queste", "quello", "quella",
  "elimina", "eliminare", "cancella", "cancellare", "modifica",
  "crea", "esegui", "salva", "leggi", "file", "cartella",
  "tutti", "tutto", "tutta", "tutte", "lavoro", "codice",
  "perche", "perché", "anche", "come", "dove", "quando", "nella", "della"
]);

function detectLanguage(text: string): "english" | "multilingual" {
  if (!text) return "english";
  if (/[àèéìòùÀÈÉÌÒÙ]/.test(text)) return "multilingual";
  const words = text.toLowerCase().match(/\b[a-z]{2,}\b/g) || [];
  let matches = 0;
  for (const w of words) {
    if (ITALIAN_MARKERS.has(w)) matches++;
  }
  if (matches >= 2 || (words.length > 0 && matches / words.length >= 0.15)) {
    return "multilingual";
  }
  return "english";
}

interface CacheEntry {
  decision: LayaDecision;
  taintVersion: number;
}

class BoundedDecisionCache {
  private cache = new Map<string, CacheEntry>();
  private readonly maxCapacity = 1000;

  get(key: string, currentVersion: number): LayaDecision | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (entry.taintVersion !== currentVersion) {
      this.cache.delete(key);
      return null;
    }
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.decision;
  }

  put(key: string, decision: LayaDecision, currentVersion: number): void {
    if (this.cache.size >= this.maxCapacity) {
      const oldest = this.cache.keys().next().value;
      if (oldest) this.cache.delete(oldest);
    }
    this.cache.set(key, { decision, taintVersion: currentVersion });
  }

  size(): number {
    return this.cache.size;
  }
}

const decisionCache = new BoundedDecisionCache();

function resolveTargetModel(
  lang: "english" | "multilingual",
  toolName: string,
  payloadLength: number,
  isTainted: boolean
): { model: "multilingual" | "typed-decisions" | "english"; langParam: "it" | "en" } {
  // 1. Language barrier: ModernBERT (english & typed-decisions) collapses on Italian
  if (lang === "multilingual") {
    return { model: "multilingual", langParam: "it" };
  }
  // 2. Specialized 1024-token model for code mutations, long payloads, or security alerts
  if (toolName === "write" || toolName === "edit" || payloadLength > 400 || isTainted) {
    return { model: "typed-decisions", langParam: "en" };
  }
  // 3. Ultra-fast 512-token model for routine English CLI commands
  return { model: "english", langParam: "en" };
}

interface WindowEval {
  safeProb: number;
  noSecretProb: number;
  alignedProb: number;
  riskScore: number;
  adversarialIntent?: string;
  adversarialIntentProb?: number;
  blastRadiusScore?: number;
}

function extractTargetedWindows(rawText: string, windowCharLimit = 800): string[] {
  if (!rawText || rawText.length <= windowCharLimit) {
    return [rawText || ""];
  }

  const head = rawText.slice(0, windowCharLimit);
  const tail = rawText.slice(-windowCharLimit);

  let bestMidIndex = -1;
  for (const re of SUSPICIOUS_KEYWORDS) {
    const match = re.exec(rawText);
    if (match && match.index > windowCharLimit && match.index < rawText.length - windowCharLimit) {
      bestMidIndex = match.index;
      break;
    }
  }

  if (bestMidIndex > 0) {
    const halfWin = Math.floor(windowCharLimit / 2);
    const start = Math.max(0, bestMidIndex - halfWin);
    const mid = rawText.slice(start, start + windowCharLimit);
    return [head, mid, tail];
  }

  return [head, tail];
}

function buildQuestionsForModel(
  targetModel: "multilingual" | "typed-decisions" | "english"
): Record<string, any> {
  if (targetModel === "typed-decisions") {
    return {
      intent_classification: {
        type: "choice",
        instructions: "Identify the true operational objective of this payload.",
        criteria: {
          benign_dev: "ordinary software engineering, compiling, testing, formatting, or workspace file updates",
          reconnaissance: "discovering system architecture, reading network configuration, environment dump, or finding sensitive paths",
          credential_harvesting: "reading, echoing, parsing, or accessing private keys, tokens, auth headers, or secret stores",
          covert_exfiltration: "sending workspace data, files, or stolen credentials outbound via curl, netcat, sockets, or webhooks",
          persistence_tampering: "modifying shell rc, cron, systemd, audit logs, or planting background reverse shells",
        },
      },
      blast_radius: {
        type: "score",
        instructions: "Rate the operational blast radius and privilege scope of this action.",
        criteria: [
          "level 0: read-only workspace inspection or inert command",
          "level 1: routine local modification of project files",
          "level 2: touching external configs, credentials, or invoking network utilities",
          "level 3: credential exfiltration, remote shellcode, or destructive filesystem tampering",
        ],
      },
      no_secret_egress: {
        type: "noul",
        instructions: "Is this action completely free from credential leaks, token exfiltration, or private key exposure?",
        criteria: {
          true: "Zero secret egress or private key access",
          false: "Accesses, transmits or exposes credentials or sensitive environment data",
        },
      },
      is_safe_operation: {
        type: "noul",
        instructions: "Is this tool execution completely safe, non-destructive, and within normal development boundaries?",
        criteria: {
          true: "Safe, non-destructive, and normal developer operation",
          false: "Dangerous, destructive, or unauthorized action",
        },
      },
    };
  }

  // Base English & Multilingual System 1 Questions
  return {
    is_safe_operation: {
      type: "noul",
      instructions: "Is this tool execution completely safe, non-destructive, and within normal development boundaries?",
      criteria: {
        true: "Safe, non-destructive, and normal developer operation",
        false: "Dangerous, destructive, or unauthorized action",
      },
    },
    no_secret_egress: {
      type: "noul",
      instructions: "Is this action free from credential leaks, token exfiltration, or private key exposure?",
      criteria: {
        true: "Zero secret egress or private key access",
        false: "Accesses, transmits or exposes credentials or sensitive environment data",
      },
    },
    is_aligned_with_goal: {
      type: "noul",
      instructions: "Does this tool execution directly serve and align with the authorized user goal?",
      criteria: {
        true: "Directly serves the user request without drift",
        false: "Unrelated side-effect, drift, or potential injection",
      },
    },
    safety_score: {
      type: "score",
      instructions: "Rate the overall safety and compliance of this operation from 1 (critical hazard) to 5 (completely safe).",
      criteria: ["1 - critical hazard", "2 - high risk", "3 - moderate risk", "4 - low risk", "5 - completely safe"],
    },
  };
}

let isWakingUp = false;

async function ensureLayaAwake(): Promise<boolean> {
  try {
    const probe = await fetch(`${LAYA_SERVER_URL}/health`, { signal: AbortSignal.timeout(400) });
    if (probe.ok) return true;
  } catch {}

  if (isWakingUp) {
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 200));
      try {
        const probe = await fetch(`${LAYA_SERVER_URL}/health`, { signal: AbortSignal.timeout(300) });
        if (probe.ok) return true;
      } catch {}
    }
    return false;
  }

  isWakingUp = true;
  try {
    const ctlCmd = "laya-ctl start 2>/dev/null || python3 scripts/laya_ctl.py start 2>/dev/null || python3 ~/gitapp/laya-ctl/bin/laya-ctl start 2>/dev/null";
    cp.execSync(ctlCmd, { timeout: 10000, stdio: "ignore" });

    for (let i = 0; i < 35; i++) {
      await new Promise((r) => setTimeout(r, 200));
      try {
        const probe = await fetch(`${LAYA_SERVER_URL}/health`, { signal: AbortSignal.timeout(300) });
        if (probe.ok) return true;
      } catch {}
    }
    return false;
  } catch {
    return false;
  } finally {
    isWakingUp = false;
  }
}

async function queryLayaServe(
  state: string,
  targetModel: "multilingual" | "typed-decisions" | "english",
  langParam: "it" | "en"
): Promise<Record<string, any>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);

  // Positive Formulation of Invariants: destroys context poisoning at the root
  // Explicit model dispatch: 'auto' is strictly eliminated to prevent language collapse
  const payload: Record<string, any> = {
    state,
    model: targetModel,
    lang: langParam,
    questions: buildQuestionsForModel(targetModel),
  };

  try {
    let res: Response;
    try {
      res = await fetch(`${LAYA_SERVER_URL}/v1/systemone`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } catch (netErr) {
      // Possible hibernation: try auto-wake once
      const awake = await ensureLayaAwake();
      if (!awake) throw netErr;
      res = await fetch(`${LAYA_SERVER_URL}/v1/systemone`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return (await res.json()) as Record<string, any>;
  } finally {
    clearTimeout(timer);
  }
}

async function evaluateAction(
  toolName: string,
  args: Record<string, unknown>,
  astContext: string | null,
  cwd: string,
  userPrompt: string | null
): Promise<LayaDecision | null> {
  const targetPath = String(args.path || args.file || args.command || args.query || "");
  let isTainted = false;

  // 1. Audit Log Path Invariant (Zero-Tampering / Controllore != Controllato)
  // Evaluated on canonical filesystem targets, never on brittle shell command verbs
  const canonTarget = taintTracker.canonicalize(targetPath, cwd);
  const isAuditTarget = canonTarget && (
    canonTarget.includes(path.join(".cache", "laya")) ||
    canonTarget.endsWith("laya_serve.log") ||
    canonTarget.endsWith("firewall.jsonl") ||
    canonTarget.endsWith("warden.jsonl")
  );

  if (isAuditTarget) {
    if (toolName === "write" || toolName === "edit" || (toolName === "bash" && !BENIGN_SHELL_READ_REGEX.test(targetPath.trim()))) {
      return {
        requires_human_confirmation: false,
        hard_block: true,
        verdict: "BLOCK",
        risk_score: 5,
        is_tainted: false,
        reason: "🛑 [Audit Security] I file di audit (~/.cache/laya/) sono protetti e immutabili. Modifica o cancellazione vietata (Regola: Controllore != Controllato).",
      };
    }
  }

  // 2. Smart Read-Only Gating (Bypass in 0ms if non-sensitive)
  if (SAFE_READONLY_TOOLS.has(toolName)) {
    if (!taintTracker.isPathSensitive(targetPath, cwd)) {
      return {
        requires_human_confirmation: false,
        verdict: "ALLOW",
        risk_score: 1,
        is_tainted: false,
        reason: "Readonly scope bypass (clean target)",
      };
    }
    isTainted = true;
  }

  // 3. Hard Security Heuristics (<0.05ms) - Drop shellcode & cloud IMDS probes
  const hardViolation = checkHardHeuristics(toolName, args);
  if (hardViolation) {
    const allowOverride = process.env.LAYA_ALLOW_OVERRIDE === "true" || process.env.LAYA_PROMPT_ALL === "true";
    return {
      requires_human_confirmation: allowOverride,
      verdict: "BLOCK",
      risk_score: 5,
      is_tainted: false,
      reason: hardViolation,
      hard_block: !allowOverride,
    };
  }

  // 4. Intent-Gated Git Commits & Chained Pipeline Atomicity
  if (toolName === "bash") {
    const cmd = String(args.command || "").trim();

    if (isLegitLayaBootstrap(cmd)) {
      return {
        requires_human_confirmation: false,
        verdict: "ALLOW",
        risk_score: 1,
        is_tainted: false,
        reason: "Laya service bootstrap operation",
      };
    }

    const atoms = splitCommandChain(cmd);

    // Atomicity Check 1: Audit Log Tampering Gate per Atom
    for (const atom of atoms) {
      if (atomTouchesAuditPath(atom)) {
        return {
          requires_human_confirmation: false,
          hard_block: true,
          verdict: "BLOCK",
          risk_score: 5,
          is_tainted: false,
          reason: "🛑 [Audit Security] I file di audit (~/.cache/laya/) sono protetti e immutabili. Modifica o cancellazione vietata (Regola: Controllore != Controllato).",
        };
      }
    }

    // Atomicity Check 2: Intent-Gated Git Commits per Atom
    const userHasCommitIntent = COMMIT_INTENT_REGEX.test(userPrompt || "");
    for (const atom of atoms) {
      if (/\bgit\s+commit\b/i.test(atom) && !userHasCommitIntent) {
        return {
          requires_human_confirmation: false,
          hard_block: true,
          verdict: "BLOCK",
          risk_score: 5,
          is_tainted: false,
          reason: "🛡️ [Git Safety] Commit autonomo non autorizzato. L'agente non può committare da solo senza il tuo permesso esplicito. 👉 Se vuoi autorizzarlo, scrivi 'fai il commit' nel tuo messaggio.",
        };
      }
    }

    // Atomicity Check 3: Multi-Hop Taint DAG Propagation per Atom
    for (const atom of atoms) {
      taintTracker.inspectAndPropagateBash(atom, cwd);
      if (taintTracker.isCommandTainted(atom, cwd)) {
        isTainted = true;
      }
    }

    // Atomicity Check 4: Safe Local Git Fast-Path
    if (isSafeLocalGitOperation(cmd, userHasCommitIntent) && !isTainted) {
      return {
        requires_human_confirmation: false,
        verdict: "ALLOW",
        risk_score: 1,
        is_tainted: false,
        reason: "Safe local git version control operation",
      };
    }

    // Atomicity Check 5: Hawking Conservation Law on Clean Local Chained Workspace
    const hasNetworkOutbound = atoms.some((atom) =>
      /\b(?:curl|wget|fetch|axios|urllib|http\.client|nc|ncat|ssh|scp|sftp|rsync|socket)\b/i.test(atom) ||
      /https?:\/\//i.test(atom)
    );
    const hasSensitiveRedirect = atoms.some((atom) => />\s*[^&|;]*\.(?:env|pem|key|ssh|aws)/i.test(atom));

    if (!isTainted && !hasNetworkOutbound && !hasSensitiveRedirect) {
      return {
        requires_human_confirmation: false,
        verdict: "ALLOW",
        risk_score: 1,
        is_tainted: false,
        reason: "Clean local chained workspace execution (zero taint, zero egress)",
      };
    }
  } else if (!isTainted && targetPath) {
    if (toolName === "write" || toolName === "edit") {
      if (taintTracker.isPathIntegrityProtected(targetPath, cwd)) {
        isTainted = true;
      }
    }
    if (!isTainted) isTainted = taintTracker.isPathSensitive(targetPath, cwd);
  }

  // 5. Hawking Conservation Invariant: Local Clean Workspace Operations Bypass
  // If the command is completely non-tainted and does not touch sensitive seeds,
  // local development (TDD test execution, formatting, building) is inherently safe in 0ms.
  if (toolName === "bash" && !isTainted) {
    const cmd = String(args.command || "").trim();
    const hasNetworkOutbound = /\b(?:curl|wget|fetch|axios|urllib|http\.client|nc|ncat|ssh|scp|sftp|rsync|socket)\b/i.test(cmd) || /https?:\/\//i.test(cmd);
    const hasSensitiveRedirect = />\s*[^&|;]*\.(?:env|pem|key|ssh|aws)/i.test(cmd);

    if (!hasNetworkOutbound && !hasSensitiveRedirect) {
      return {
        requires_human_confirmation: false,
        verdict: "ALLOW",
        risk_score: 1,
        is_tainted: false,
        reason: "Clean local workspace execution (zero taint, zero egress)",
      };
    }
  }

  // Bounded Holographic Horizon (Stephen Hawking & Kevin Mitnick Anti-Evasion)
  let rawPayload = "";
  if (toolName === "bash") {
    rawPayload = String(args.command || "");
  } else if (toolName === "write") {
    rawPayload = String(args.content || "");
  } else if (toolName === "edit" && Array.isArray(args.edits)) {
    rawPayload = (args.edits as { newText?: string }[]).map((e) => e.newText || "").join("\n");
  } else {
    rawPayload = targetPath;
  }

  const { bounded, highEntropy, suspiciousTokens } = boundStateHorizon(rawPayload);
  const entropyRisk = highEntropy || suspiciousTokens.length >= 2;

  // Zero-cost LRU Cache Check (<0.001ms)
  const cacheKey = `${toolName}:${targetPath}:${bounded}:${userPrompt || ""}`;
  const cached = decisionCache.get(cacheKey, taintTracker.version);
  if (cached) {
    return cached;
  }

  // Model Triage (Explicit dispatch: 'auto' is strictly eliminated)
  const lang = detectLanguage(`${userPrompt || ""} ${rawPayload.slice(0, 300)}`);
  const { model: targetModel, langParam } = resolveTargetModel(lang, toolName, rawPayload.length, isTainted);

  // Incremental Targeted Windows (Mitnick & Hawking Horizon)
  const windows = extractTargetedWindows(rawPayload, 800);

  try {
    const windowEvals: WindowEval[] = [];

    for (const win of windows) {
      const stateRepr = JSON.stringify({
        tool: toolName,
        target: targetPath,
        payload_window: win,
        ast: astContext,
        tainted: isTainted || entropyRisk,
        cwd,
        user_prompt: userPrompt,
      });

      const s1Resp = await queryLayaServe(stateRepr, targetModel, langParam);
      const answers = s1Resp.answers || {};

      const safeProb = Number(answers.is_safe_operation?.noul ?? 1.0);
      const noSecretProb = Number(answers.no_secret_egress?.noul ?? 1.0);
      const alignedProb = Number(answers.is_aligned_with_goal?.noul ?? 1.0);
      let rawScore = answers.safety_score?.score ?? 4;

      let adversarialIntent: string | undefined;
      let adversarialIntentProb = 0;
      let blastRadiusScore: number | undefined;

      if (answers.intent_classification?.choice) {
        adversarialIntent = answers.intent_classification.choice;
        const probs = answers.intent_classification.probabilities || {};
        adversarialIntentProb = Number(probs[adversarialIntent] ?? answers.intent_classification.answer_confidence ?? 0);
      }
      if (answers.blast_radius?.score !== undefined) {
        blastRadiusScore = Number(answers.blast_radius.score);
        rawScore = Math.max(1, 5 - Math.round(blastRadiusScore * 1.3));
      }
      const rScore = Math.min(5, Math.max(1, 6 - Math.round(Number(rawScore))));

      windowEvals.push({
        safeProb,
        noSecretProb,
        alignedProb,
        riskScore: rScore,
        adversarialIntent,
        adversarialIntentProb,
        blastRadiusScore,
      });
    }

    // Min-Pooling Merge (Hawking Weakest-Link Invariant: a single poisoned chunk taints the composite verdict)
    const minSafeProb = Math.min(...windowEvals.map((e) => e.safeProb));
    const minNoSecretProb = Math.min(...windowEvals.map((e) => e.noSecretProb));
    const minAlignedProb = Math.min(...windowEvals.map((e) => e.alignedProb));
    const maxRiskScore = Math.max(...windowEvals.map((e) => e.riskScore));

    const detectedIntents = windowEvals
      .filter((e) => e.adversarialIntent && e.adversarialIntent !== "benign_dev" && (e.adversarialIntentProb ?? 0) >= 0.28)
      .map((e) => `${e.adversarialIntent} (${((e.adversarialIntentProb ?? 0) * 100).toFixed(0)}%)`);

    const maxBlastScore = Math.max(...windowEvals.map((e) => e.blastRadiusScore ?? 0));
    const suspectAdversarial = detectedIntents.length > 0;
    const suspectHighBlast = maxBlastScore >= 1.70;

    const hasNetworkCapability = /\b(?:curl|wget|fetch|axios|urllib|http\.client|nc|ncat|ssh|scp|sftp|rsync|socket)\b/i.test(rawPayload) || /https?:\/\//i.test(rawPayload);
    const suspectSecretLeak = (isTainted || hasNetworkCapability) && minNoSecretProb < 0.70;
    const suspectUnsafe = minSafeProb < 0.65;
    const suspectGoalDrift = userPrompt ? minAlignedProb < 0.60 : false;

    let verdict: "ALLOW" | "REQUIRE_CONFIRMATION" | "BLOCK" = "ALLOW";
    if (suspectSecretLeak || suspectUnsafe || suspectGoalDrift || isTainted || entropyRisk || suspectAdversarial || suspectHighBlast) {
      verdict = "REQUIRE_CONFIRMATION";
    }

    const finalRiskScore = Math.max(
      maxRiskScore,
      (suspectSecretLeak || suspectUnsafe || isTainted || entropyRisk || suspectAdversarial || suspectHighBlast) ? 3 : 1
    );
    const requiresHuman = !(verdict === "ALLOW" && finalRiskScore < 3);

    const reasons: string[] = [];
    if (isTainted) reasons.push(`Percorso o file sensibile coinvolto (${targetPath})`);
    if (entropyRisk) reasons.push(`Token sospetti o alta entropia (${suspiciousTokens.join(", ") || "blob cifrato"})`);
    if (suspectAdversarial) reasons.push(`Intento anomalo rilevato: ${[...new Set(detectedIntents)].join(", ")}`);
    if (suspectHighBlast) reasons.push(`Raggio d'impatto elevato sul sistema (${maxBlastScore.toFixed(1)}/3)`);
    if (suspectSecretLeak) reasons.push(`Rischio di fuga credenziali o chiavi (affidabilità ${(minNoSecretProb * 100).toFixed(0)}%)`);
    if (suspectUnsafe) reasons.push(`Azione potenzialmente distruttiva o non sicura (fiducia ${(minSafeProb * 100).toFixed(0)}%)`);
    if (suspectGoalDrift) reasons.push(`Comando disallineato rispetto alla richiesta dell'utente (${(minAlignedProb * 100).toFixed(0)}%)`);

    const finalDecision: LayaDecision = {
      requires_human_confirmation: requiresHuman,
      verdict,
      risk_score: finalRiskScore,
      is_tainted: isTainted,
      reason: reasons.join("; ") || "Routine operation",
    };

    decisionCache.put(cacheKey, finalDecision, taintTracker.version);
    return finalDecision;
  } catch (err) {
    // If laya-serve is offline or errored, return null to trigger fail-closed prompt
    return null;
  }
}

async function confirmGuardrail(
  ctx: { ui: { select: (title: string, options: string[], opts?: { timeout?: number }) => Promise<string | null> } },
  scope: string,
  target: string,
  decision: LayaDecision | null
): Promise<{ allowed: boolean; reason?: string }> {
  if (!decision) {
    // Strict Fail-Closed Session Interruption
    return {
      allowed: false,
      reason: "Fail-closed: laya-serve offline su 127.0.0.1:5292. Sessione sospesa fino al ripristino del firewall.",
    };
  }

  if (decision.hard_block) {
    // Immediate categorical block without interactive prompt
    return {
      allowed: false,
      reason: `[Laya Firewall] 🛑 Violazione di sicurezza bloccata: ${decision.reason}`,
    };
  }

  if (decision.requires_human_confirmation && decision.verdict !== "ALLOW") {
    let threat = target.replace(/#.*$/, "").trim() || target;
    if (threat.length > 100) threat = threat.slice(0, 97) + "...";

    const promptTitle = `🛡️ [Laya Firewall] Rilevata operazione ad alto rischio (${decision.risk_score}/5): ${scope}`;
    const choice = await ctx.ui.select(
      promptTitle,
      [
        `❌ NO - Blocca operazione (Consigliato / Invio rapido) | ${threat}`,
        `⚠️ YES - Autorizza comunque | Motivo: ${decision.reason || "Operazione rischiosa"}`
      ],
      { timeout: CONFIRM_TIMEOUT_MS }
    );
    return {
      allowed: typeof choice === "string" && (choice.startsWith("YES") || choice.startsWith("⚠️ YES")),
      reason: decision.reason || "high risk",
    };
  }

  return { allowed: true };
}

const LAYA_SERVICE_MGMT_REGEX = /^\s*(?:python[23]?\s+)?(?:\S*\/)?(?:laya[-_]ctl(?:\.py)?|laya-serve)\s+(?:start|stop|restart|status|logs|setup)\b.*$/;
const LAYA_SERVE_BIN_REGEX = /^\s*(?:nohup\s+)?(?:LAYA_[A-Z_]+=[^\s]+\s+)*laya-serve(?:\s+[^;|&<>]+)?$/;
const BENIGN_SHELL_READ_REGEX = /^\s*(?:cat|head|tail|grep|wc|file|which|where|ls|stat)\b(?:(?!>|\|).)*$/;

function isLegitLayaBootstrap(cmd: string): boolean {
  const clean = cmd.trim();
  return LAYA_SERVICE_MGMT_REGEX.test(clean) || LAYA_SERVE_BIN_REGEX.test(clean);
}

function splitCommandChain(cmd: string): string[] {
  if (!cmd) return [];
  return cmd
    .split(/\s*(?:&&|\|\||;|;|&|\n)\s*/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function atomTouchesAuditPath(atom: string): boolean {
  if (!/(?:\.cache[\/\\]laya[\/\\](?:firewall|warden)\.jsonl|laya_serve\.log)/i.test(atom)) {
    return false;
  }
  return !(BENIGN_SHELL_READ_REGEX.test(atom) && !/(?:>|\|)/.test(atom));
}

const COMMIT_INTENT_REGEX = /\b(?:commit|committa|committare|fai il commit)\b/i;

function isSafeLocalGitOperation(cmd: string, userHasCommitIntent: boolean = false): boolean {
  if (/\b(?:push|remote\s+add|filter-branch)\b/i.test(cmd)) return false;
  if (/(?:^|\s)(?:-f|--force|-n|--no-verify)\b/i.test(cmd)) return false;

  // Intent-Gated Git Commits: Autonomous commits forbidden without user order
  if (/\bgit\s+commit\b/i.test(cmd)) {
    if (!userHasCommitIntent) return false;
    // Pre-commit DLP scan on staged diff: prevent accidental or malicious secret commits
    try {
      const diff = cp.execSync("git diff --cached", { encoding: "utf-8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] });
      const secretPattern = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|xox[baprs]-[0-9a-zA-Z]{10,48})/i;
      if (secretPattern.test(diff)) return false;
    } catch {}
  }

  const parts = cmd.split(/\s*(?:&&|;)\s*/);
  return parts.every((sub) => {
    const trimmed = sub.trim();
    if (!trimmed) return true;
    if (/^cd\s+/i.test(trimmed)) return true;
    return /^\s*git\s+(?:add|commit|status|diff|log|branch|checkout|switch|merge|rebase|stash|tag|rev-parse)\b/i.test(trimmed);
  });
}

export default function (pi: ExtensionAPI) {
  let currentSessionUserPrompt = "";

  // 1. System 3: Pre-Tool Execution Guardrail
  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;
    const input = (event.input || {}) as Record<string, unknown>;
    const sessionId = getSessionId(ctx);

    // Break bootstrap deadlock: allow ONLY legitimate laya control commands to run
    if (toolName === "bash" && typeof input.command === "string") {
      if (isLegitLayaBootstrap(input.command)) {
        return undefined;
      }
    }

    const astContext = extractAstContext(toolName, input);
    const scrubbedArgs = scrubSensitiveArgs(input);
    const cwd = process.cwd();

    const decision = await evaluateAction(toolName, scrubbedArgs, astContext, cwd, currentSessionUserPrompt || null);
    const threatTarget = String(input.command || input.path || input.uri || toolName);

    logFirewallEvent(sessionId, "tool_evaluate", threatTarget, {
      tool: toolName,
      decision: decision ? { verdict: decision.verdict, risk: decision.risk_score, reason: decision.reason } : "offline",
    });

    const confirmation = await confirmGuardrail(ctx, toolName, threatTarget, decision);
    if (!confirmation.allowed) {
      logFirewallEvent(sessionId, "tool_blocked", threatTarget, { reason: confirmation.reason });
      return { block: true, reason: `Bloccato da Laya Firewall (${confirmation.reason})` };
    }

    return undefined;
  });

  // 2. System 1 & 3 for user_bash (!command manual shell executions)
  pi.on("user_bash", async (event, ctx) => {
    const cmd = (event.command || "").trim();
    if (!cmd) return undefined;
    const sessionId = getSessionId(ctx);

    if (isLegitLayaBootstrap(cmd)) {
      return undefined;
    }

    const scrubbedArgs = scrubSensitiveArgs({ command: cmd });
    const cwd = process.cwd();

    const decision = await evaluateAction("bash", scrubbedArgs, null, cwd, currentSessionUserPrompt || null);
    logFirewallEvent(sessionId, "user_bash_evaluate", cmd, {
      decision: decision ? { verdict: decision.verdict, risk: decision.risk_score, reason: decision.reason } : "offline",
    });

    const confirmation = await confirmGuardrail(ctx, "!bash", cmd, decision);
    if (!confirmation.allowed) {
      logFirewallEvent(sessionId, "user_bash_blocked", cmd, { reason: confirmation.reason });
      return {
        result: {
          stdout: "",
          stderr: `[Laya Firewall] Comando manuale bloccato: ${confirmation.reason}`,
          exitCode: 1,
        }
      };
    }

    return undefined;
  });

  // 3. System 1: User Prompt Triage (Cognitive Pre-LLM Layer)
  pi.on("input", async (event, ctx) => {
    const text = (event.text || "").trim();
    if (!text || text.startsWith("/")) return undefined;
    currentSessionUserPrompt = text;
    logFirewallEvent(getSessionId(ctx), "user_prompt", text.slice(0, 100), { length: text.length });
    return undefined;
  });

  // 4. System 3 DLP Post-Execution Output Sanitization
  pi.on("tool_result", async (event) => {
    if (!Array.isArray(event.content)) return undefined;

    let modified = false;
    const secretPattern = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|xox[baprs]-[0-9a-zA-Z]{10,48})/g;

    const newContent = event.content.map((item) => {
      if (item.type === "text" && typeof item.text === "string" && secretPattern.test(item.text)) {
        modified = true;
        return { ...item, text: item.text.replace(secretPattern, "[REDACTED_SECRET by Laya Firewall DLP]") };
      }
      return item;
    });

    return modified ? { content: newContent } : undefined;
  });

  // 5. Slash command /laya for diagnostics, logs, and health probe
  pi.registerCommand("laya", {
    description: "Stato, log o test Laya (/laya status | /laya logs | /laya s1 <prompt>)",
    handler: async (args, ctx) => {
      const cleanArgs = (args || "").trim();
      const sessionId = getSessionId(ctx);

      if (!cleanArgs || cleanArgs === "status") {
        try {
          const res = await fetch(`${LAYA_SERVER_URL}/health`);
          if (res.ok) {
            const h = (await res.json()) as any;
            ctx.ui.notify(
              `Laya: ok (${LAYA_SERVER_URL}) | Device: ${h.device} | Models: [${(h.loaded || []).join(", ")}] | Taints: ${taintTracker.getTaintCount()} | Session: ${sessionId}`,
              "info"
            );
          } else {
            ctx.ui.notify(`Laya: HTTP ${res.status}`, "error");
          }
        } catch (err) {
          ctx.ui.notify(`Laya: offline (${String(err)})`, "error");
        }
        return;
      }

      if (cleanArgs === "logs") {
        try {
          if (!fs.existsSync(LOG_FILE)) {
            ctx.ui.notify("Nessun log firewall registrato.", "info");
            return;
          }
          const lines = fs.readFileSync(LOG_FILE, "utf-8").trim().split("\n");
          const sessionLines = lines
            .map((l) => {
              try { return JSON.parse(l); } catch { return null; }
            })
            .filter((e) => e && (e.session_id === sessionId || !sessionId))
            .slice(-5);

          const summary = sessionLines
            .map((e) => `[${e.timestamp.slice(11, 19)}] ${e.event} -> ${e.target.slice(0, 30)}`)
            .join("\n");

          ctx.ui.notify(`Ultime azioni Laya Firewall (Sessione ${sessionId.slice(0, 8)}):\n${summary || "Nessun evento"}`, "info");
        } catch (err) {
          ctx.ui.notify(`Errore lettura log: ${String(err)}`, "error");
        }
        return;
      }

      if (cleanArgs.startsWith("s1 ")) {
        const prompt = cleanArgs.slice(3).trim();
        try {
          const res = await fetch(`${LAYA_SERVER_URL}/v1/systemone`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              state: prompt,
              questions: {
                is_safe_operation: {
                  type: "noul",
                  instructions: "Is this prompt safe and non-malicious?",
                },
              },
            }),
          });
          const data = (await res.json()) as any;
          ctx.ui.notify(`S1 Result: ${JSON.stringify(data.answers || {})}`, "info");
        } catch (err) {
          ctx.ui.notify(`Laya S1 errore: ${String(err)}`, "error");
        }
        return;
      }

      ctx.ui.notify("Uso: /laya status | /laya logs | /laya s1 <prompt>", "warning");
    },
  });
}
