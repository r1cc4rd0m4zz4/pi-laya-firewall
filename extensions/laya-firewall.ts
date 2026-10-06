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
    "~/.pi/agent",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/master.passwd",
  ];

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

    // 1. Redirection: cat secret > dst.txt
    const redirMatch = command.match(/(?:cat|grep|head|tail|base64|xxd|strings|tee)\s+([^\s|>]+)\s*>\s*([^\s|>]+)/);
    if (redirMatch && redirMatch[1] && redirMatch[2]) {
      const src = redirMatch[1].replace(/['"]/g, "");
      const dst = redirMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(dst, cwd);
        return;
      }
    }

    // 2. Pipe to tee: cat secret | tee dst.txt
    const teeMatch = command.match(/(?:cat|grep|head|tail|strings)\s+([^\s|>]+)\s*\|\s*(?:sudo\s+)?tee\s+(?:-[a-zA-Z]+\s+)*([^\s|>]+)/i);
    if (teeMatch && teeMatch[1] && teeMatch[2]) {
      const src = teeMatch[1].replace(/['"]/g, "");
      const dst = teeMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(dst, cwd);
        return;
      }
    }

    // 3. File Copy / Move / Rsync: cp secret dst.txt
    const cpMatch = command.match(/\b(?:cp|mv|rsync|Copy-Item|Move-Item)\s+(?:-[a-zA-Z0-9]+\s+)*([^\s]+)\s+([^\s]+)/i);
    if (cpMatch && cpMatch[1] && cpMatch[2]) {
      const src = cpMatch[1].replace(/['"]/g, "");
      const dst = cpMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(dst, cwd);
        return;
      }
    }

    // 4. Archive packing: tar -czf leak.tar.gz .env / zip leak.zip .env
    const archiveMatch = command.match(/\b(?:tar\s+-[a-zA-Z0-9]*f|zip\s+(?:-[a-zA-Z0-9]+\s+)*)\s*([^\s]+)\s+([^\s]+)/i);
    if (archiveMatch && archiveMatch[1] && archiveMatch[2]) {
      const dst = archiveMatch[1].replace(/['"]/g, "");
      const src = archiveMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(dst, cwd);
        return;
      }
    }

    // 5. Block copy: dd if=secret of=dst.txt
    const ddMatch = command.match(/\bdd\s+.*if=([^\s]+)\s+.*of=([^\s]+)/i);
    if (ddMatch && ddMatch[1] && ddMatch[2]) {
      const src = ddMatch[1].replace(/['"]/g, "");
      const dst = ddMatch[2].replace(/['"]/g, "");
      if (this.isPathSensitive(src, cwd)) {
        this.markTainted(dst, cwd);
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

async function queryLayaServe(
  state: string,
  targetModel: "multilingual" | "typed-decisions" | "english",
  langParam: "it" | "en"
): Promise<Record<string, any>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);

  // Positive Formulation of Invariants: destroys context poisoning at the root
  // Explicit model dispatch: 'auto' is strictly eliminated to prevent language collapse
  const payload: Record<string, any> = {
    state,
    model: targetModel,
    lang: langParam,
    questions: {
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
    },
  };

  try {
    const res = await fetch(`${LAYA_SERVER_URL}/v1/systemone`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
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
  // 1. Smart Read-Only Gating (Bypass in 0ms only if completely non-sensitive)
  const targetPath = String(args.path || args.file || args.command || args.query || "");
  let isTainted = false;

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

  // 2. Hard Security Heuristics (<0.05ms) - Default Hard Block without prompt
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

  // 3. Taint Tracking Propagation & Matching
  if (toolName === "bash") {
    const cmd = String(args.command || "");
    taintTracker.inspectAndPropagateBash(cmd, cwd);
    if (!isTainted) isTainted = taintTracker.isCommandTainted(cmd, cwd);
  } else if (!isTainted && targetPath) {
    isTainted = taintTracker.isPathSensitive(targetPath, cwd);
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
      const rawScore = answers.safety_score?.score ?? 4;
      const rScore = Math.min(5, Math.max(1, 6 - Math.round(Number(rawScore))));

      windowEvals.push({ safeProb, noSecretProb, alignedProb, riskScore: rScore });
    }

    // Min-Pooling Merge (Hawking Weakest-Link Invariant: a single poisoned chunk taints the composite verdict)
    const minSafeProb = Math.min(...windowEvals.map((e) => e.safeProb));
    const minNoSecretProb = Math.min(...windowEvals.map((e) => e.noSecretProb));
    const minAlignedProb = Math.min(...windowEvals.map((e) => e.alignedProb));
    const maxRiskScore = Math.max(...windowEvals.map((e) => e.riskScore));

    const suspectSecretLeak = minNoSecretProb < 0.95;
    const suspectUnsafe = minSafeProb < 0.70;
    const suspectGoalDrift = userPrompt ? minAlignedProb < 0.60 : false;

    let verdict: "ALLOW" | "REQUIRE_CONFIRMATION" | "BLOCK" = "ALLOW";
    if (suspectSecretLeak || suspectUnsafe || suspectGoalDrift || isTainted || entropyRisk) {
      verdict = "REQUIRE_CONFIRMATION";
    }

    const finalRiskScore = Math.max(maxRiskScore, (suspectSecretLeak || suspectUnsafe || isTainted || entropyRisk) ? 3 : 1);
    const requiresHuman = !(verdict === "ALLOW" && finalRiskScore < 3);

    const reasons: string[] = [];
    if (isTainted) reasons.push("Target path is tainted (credential source)");
    if (entropyRisk) reasons.push(`Anomalous entropy / suspicious tokens detected (${suspiciousTokens.join(", ") || "high entropy blob"})`);
    if (suspectSecretLeak) reasons.push(`Positive secret safety below threshold (min egress confidence ${(minNoSecretProb * 100).toFixed(0)}%)`);
    if (suspectUnsafe) reasons.push(`Operation safety below threshold (min safe confidence ${(minSafeProb * 100).toFixed(0)}%)`);
    if (suspectGoalDrift) reasons.push(`Action alignment drifts from user prompt (${(minAlignedProb * 100).toFixed(0)}%)`);

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
      reason: `[Laya Firewall] Violazione critica bloccata categoricamente: ${decision.reason}`,
    };
  }

  if (decision.requires_human_confirmation && decision.verdict !== "ALLOW") {
    let threat = target.replace(/#.*$/, "").trim() || target;
    if (threat.length > 120) threat = threat.slice(0, 117) + "...";

    const promptTitle = `Laya Firewall [${decision.verdict} Rischio ${decision.risk_score}/5]: ${scope}`;
    const choice = await ctx.ui.select(
      promptTitle,
      [
        `NO - Blocca (Default) | Target: ${threat}`,
        `YES - Autorizza rischioso | Motivo: ${decision.reason || "Rischio elevato"}`
      ],
      { timeout: CONFIRM_TIMEOUT_MS }
    );
    return {
      allowed: typeof choice === "string" && choice.startsWith("YES"),
      reason: decision.reason || "high risk",
    };
  }

  return { allowed: true };
}

const LAYA_SERVICE_MGMT_REGEX = /^\s*(?:python[23]?\s+)?(?:\.\/)?(?:scripts\/)?laya_ctl(?:\.py)?\s+(?:start|stop|restart|status)(?:\s+--foreground)?\s*$/;
const LAYA_SERVE_BIN_REGEX = /^\s*(?:nohup\s+)?(?:LAYA_[A-Z_]+=[^\s]+\s+)*laya-serve(?:\s+[^;|&<>]+)?$/;

function isLegitLayaBootstrap(cmd: string): boolean {
  const clean = cmd.trim();
  return LAYA_SERVICE_MGMT_REGEX.test(clean) || LAYA_SERVE_BIN_REGEX.test(clean);
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
