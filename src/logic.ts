import type { Hono } from "hono";
import { connect } from "tls";


// ATXP: requirePayment only fires inside an ATXP context (set by atxpHono middleware).
// For raw x402 requests, the existing @x402/hono middleware handles the gate.
// If neither protocol is active (ATXP_CONNECTION unset), tryRequirePayment is a no-op.
async function tryRequirePayment(price: number): Promise<void> {
  if (!process.env.ATXP_CONNECTION) return;
  try {
    const { requirePayment } = await import("@atxp/server");
    const BigNumber = (await import("bignumber.js")).default;
    await requirePayment({ price: BigNumber(price) });
  } catch (e: any) {
    if (e?.code === -30402) throw e;
  }
}

// ─── Cache ──────────────────────────────────────────────────────────────────

interface CacheEntry { data: any; ts: number }
const cache = new Map<string, CacheEntry>();
const CACHE_TTL = 300_000; // 5 min

function cached<T>(key: string): T | null {
  const e = cache.get(key);
  return e && Date.now() - e.ts < CACHE_TTL ? (e.data as T) : null;
}
function setCache(key: string, data: any) { cache.set(key, { data, ts: Date.now() }); }

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractDomain(target: string): string {
  try {
    if (target.startsWith("http")) return new URL(target).hostname;
    if (target.includes(".") && !target.startsWith("0x")) return target.replace(/^www\./, "");
    return target;
  } catch { return target; }
}

function isWallet(target: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(target);
}

function isIP(target: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target);
}

async function dnsQuery(domain: string, type: string): Promise<any[]> {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
    });
    if (!resp.ok) return [];
    const data = await resp.json() as any;
    return data.Answer || [];
  } catch { return []; }
}

// ─── SSL Check ──────────────────────────────────────────────────────────────

interface SSLResult {
  valid: boolean;
  issuer: string;
  subject: string;
  daysUntilExpiry: number;
  protocol: string;
  grade: "A+" | "A" | "B" | "C" | "F";
  score: number; // 0-100
  details: string[];
}

async function checkSSL(domain: string): Promise<SSLResult> {
  const cacheKey = `ssl_${domain}`;
  const c = cached<SSLResult>(cacheKey);
  if (c) return c;

  try {
    // Use a TLS connection to get cert info
    const resp = await fetch(`https://${domain}`, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });

    // Check various SSL indicators
    const isHttps = resp.url.startsWith("https://");
    const hasHSTS = !!resp.headers.get("strict-transport-security");
    const details: string[] = [];
    let score = 0;

    if (isHttps) {
      score += 40;
      details.push("HTTPS active");
    } else {
      details.push("NO HTTPS — critical security issue");
    }

    if (hasHSTS) {
      score += 20;
      const hsts = resp.headers.get("strict-transport-security") || "";
      const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || "0");
      if (maxAge >= 31536000) { score += 10; details.push(`HSTS max-age=${maxAge} (1yr+)`); }
      else if (maxAge >= 86400) { score += 5; details.push(`HSTS max-age=${maxAge} (weak)`); }
      if (hsts.includes("includeSubDomains")) { score += 5; details.push("HSTS includeSubDomains"); }
      if (hsts.includes("preload")) { score += 5; details.push("HSTS preload"); }
    } else {
      details.push("No HSTS header");
    }

    // Try to get cert details via external API
    let issuer = "unknown", subject = domain, daysUntilExpiry = -1, protocol = "TLS";
    try {
      const certResp = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
        signal: AbortSignal.timeout(5000),
      });
      if (certResp.ok) {
        const certs = await certResp.json() as any[];
        if (certs.length > 0) {
          const latest = certs[0];
          issuer = latest.issuer_name || "unknown";
          const notAfter = new Date(latest.not_after);
          daysUntilExpiry = Math.floor((notAfter.getTime() - Date.now()) / 86400000);
          if (daysUntilExpiry > 30) { score += 20; details.push(`Cert valid ${daysUntilExpiry} days`); }
          else if (daysUntilExpiry > 0) { score += 10; details.push(`Cert expiring in ${daysUntilExpiry} days — renew soon`); }
          else { details.push("Cert EXPIRED"); }
        }
      }
    } catch { /* cert lookup optional */ }

    const grade: SSLResult["grade"] = score >= 90 ? "A+" : score >= 75 ? "A" : score >= 50 ? "B" : score >= 25 ? "C" : "F";

    const result: SSLResult = { valid: isHttps, issuer, subject, daysUntilExpiry, protocol, grade, score: Math.min(100, score), details };
    setCache(cacheKey, result);
    return result;
  } catch (e: any) {
    return { valid: false, issuer: "N/A", subject: domain, daysUntilExpiry: -1, protocol: "N/A", grade: "F", score: 0, details: [`SSL check failed: ${e.message}`] };
  }
}

// ─── DNS Check ──────────────────────────────────────────────────────────────

interface DNSResult {
  hasA: boolean;
  hasAAAA: boolean;
  hasMX: boolean;
  hasTXT: boolean;
  hasNS: boolean;
  hasSPF: boolean;
  hasDMARC: boolean;
  hasDNSSEC: boolean;
  nameservers: string[];
  score: number; // 0-100
  details: string[];
}

async function checkDNS(domain: string): Promise<DNSResult> {
  const cacheKey = `dns_${domain}`;
  const c = cached<DNSResult>(cacheKey);
  if (c) return c;

  const [aRecs, aaaaRecs, mxRecs, txtRecs, nsRecs] = await Promise.all([
    dnsQuery(domain, "A"),
    dnsQuery(domain, "AAAA"),
    dnsQuery(domain, "MX"),
    dnsQuery(domain, "TXT"),
    dnsQuery(domain, "NS"),
  ]);

  // Check DMARC
  const dmarcRecs = await dnsQuery(`_dmarc.${domain}`, "TXT");

  const details: string[] = [];
  let score = 0;

  const hasA = aRecs.length > 0;
  const hasAAAA = aaaaRecs.length > 0;
  const hasMX = mxRecs.length > 0;
  const hasNS = nsRecs.length > 0;
  const hasTXT = txtRecs.length > 0;

  if (hasA) { score += 15; details.push(`${aRecs.length} A record(s)`); }
  else { details.push("No A records — domain may not resolve"); }

  if (hasAAAA) { score += 10; details.push("IPv6 (AAAA) supported"); }

  if (hasMX) { score += 15; details.push(`${mxRecs.length} MX record(s) — email configured`); }

  if (hasNS) { score += 15; details.push(`NS: ${nsRecs.slice(0, 2).map((r: any) => r.data).join(", ")}`); }

  const txtData = txtRecs.map((r: any) => r.data || "").join(" ");
  const hasSPF = txtData.includes("v=spf1");
  if (hasSPF) { score += 15; details.push("SPF configured"); }
  else { details.push("No SPF — email spoofing possible"); }

  const hasDMARC = dmarcRecs.length > 0;
  if (hasDMARC) { score += 15; details.push("DMARC configured"); }
  else { details.push("No DMARC"); }

  // Google DNSSEC check
  let hasDNSSEC = false;
  try {
    const dsRecs = await dnsQuery(domain, "DS");
    hasDNSSEC = dsRecs.length > 0;
    if (hasDNSSEC) { score += 15; details.push("DNSSEC enabled"); }
  } catch {}

  const result: DNSResult = {
    hasA, hasAAAA, hasMX, hasTXT, hasNS, hasSPF, hasDMARC, hasDNSSEC,
    nameservers: nsRecs.map((r: any) => r.data || "").slice(0, 4),
    score: Math.min(100, score),
    details,
  };
  setCache(cacheKey, result);
  return result;
}

// ─── WHOIS / Domain Age Check ───────────────────────────────────────────────

interface WHOISResult {
  domainAge: number; // days
  registrar: string;
  creationDate: string;
  expiryDate: string;
  score: number; // 0-100
  details: string[];
}

async function checkWHOIS(domain: string): Promise<WHOISResult> {
  const cacheKey = `whois_${domain}`;
  const c = cached<WHOISResult>(cacheKey);
  if (c) return c;

  const details: string[] = [];
  let score = 0;
  let domainAge = 0, registrar = "unknown", creationDate = "unknown", expiryDate = "unknown";

  try {
    // Use RDAP (the modern WHOIS replacement) — free, no rate limits
    const tld = domain.split(".").pop() || "";
    const rdapServers: Record<string, string> = {
      com: "https://rdap.verisign.com/com/v1",
      net: "https://rdap.verisign.com/net/v1",
      org: "https://rdap.org/v1",
      io: "https://rdap.nic.io/v1",
      ai: "https://rdap.nic.ai/v1",
      xyz: "https://rdap.nic.xyz/v1",
      app: "https://rdap.nic.google/v1",
      dev: "https://rdap.nic.google/v1",
    };

    const rdapBase = rdapServers[tld] || `https://rdap.org/v1`;
    const resp = await fetch(`${rdapBase}/domain/${domain}`, {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: "application/rdap+json" },
    });

    if (resp.ok) {
      const data = await resp.json() as any;

      // Extract dates from events
      for (const event of data.events || []) {
        if (event.eventAction === "registration") {
          creationDate = event.eventDate?.split("T")[0] || "unknown";
          const created = new Date(event.eventDate);
          domainAge = Math.floor((Date.now() - created.getTime()) / 86400000);
        }
        if (event.eventAction === "expiration") {
          expiryDate = event.eventDate?.split("T")[0] || "unknown";
        }
      }

      // Extract registrar from entities
      for (const entity of data.entities || []) {
        if (entity.roles?.includes("registrar")) {
          registrar = entity.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] || entity.handle || "unknown";
        }
      }
    }
  } catch { /* RDAP optional */ }

  // Score domain age
  if (domainAge > 3650) { score += 40; details.push(`Domain age: ${Math.floor(domainAge / 365)} years — well established`); }
  else if (domainAge > 730) { score += 30; details.push(`Domain age: ${Math.floor(domainAge / 365)} years — established`); }
  else if (domainAge > 365) { score += 20; details.push(`Domain age: ${Math.floor(domainAge / 365)} year(s)`); }
  else if (domainAge > 90) { score += 10; details.push(`Domain age: ${domainAge} days — relatively new`); }
  else if (domainAge > 0) { score += 5; details.push(`Domain age: ${domainAge} days — VERY NEW, higher risk`); }
  else { details.push("Domain age unknown"); score += 5; }

  // Known reputable registrars
  const reputableRegistrars = ["cloudflare", "google", "namecheap", "godaddy", "gandi", "ovh", "name.com", "porkbun"];
  if (reputableRegistrars.some(r => registrar.toLowerCase().includes(r))) {
    score += 20; details.push(`Registrar: ${registrar} (reputable)`);
  } else if (registrar !== "unknown") {
    score += 10; details.push(`Registrar: ${registrar}`);
  }

  // Expiry check
  if (expiryDate !== "unknown") {
    const daysToExpiry = Math.floor((new Date(expiryDate).getTime() - Date.now()) / 86400000);
    if (daysToExpiry > 365) { score += 20; details.push(`Expires in ${Math.floor(daysToExpiry / 365)} year(s) — committed`); }
    else if (daysToExpiry > 90) { score += 15; details.push(`Expires in ${daysToExpiry} days`); }
    else if (daysToExpiry > 0) { score += 5; details.push(`Expires in ${daysToExpiry} days — renew soon`); }
    else { details.push("Domain EXPIRED or expiry unknown"); }
  } else {
    score += 10; // neutral
  }

  // Known suspicious TLDs
  const suspiciousTLDs = ["tk", "ml", "ga", "cf", "gq", "buzz", "click", "loan", "work"];
  const tld = domain.split(".").pop() || "";
  if (suspiciousTLDs.includes(tld)) {
    score = Math.max(0, score - 20);
    details.push(`TLD .${tld} — commonly used for spam/phishing`);
  } else {
    score += 20;
  }

  const result: WHOISResult = { domainAge, registrar, creationDate, expiryDate, score: Math.min(100, score), details };
  setCache(cacheKey, result);
  return result;
}

// ─── Security Headers Check ─────────────────────────────────────────────────

interface HeadersResult {
  headers: Record<string, string>;
  missing: string[];
  score: number; // 0-100
  details: string[];
}

async function checkHeaders(domain: string): Promise<HeadersResult> {
  const cacheKey = `headers_${domain}`;
  const c = cached<HeadersResult>(cacheKey);
  if (c) return c;

  try {
    const resp = await fetch(`https://${domain}`, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });

    const secHeaders: Record<string, { weight: number; good: (v: string) => boolean }> = {
      "content-security-policy": { weight: 15, good: (v) => v.length > 10 },
      "x-frame-options": { weight: 10, good: (v) => ["DENY", "SAMEORIGIN"].includes(v.toUpperCase()) },
      "x-content-type-options": { weight: 10, good: (v) => v.toLowerCase() === "nosniff" },
      "referrer-policy": { weight: 10, good: (v) => v.length > 0 },
      "permissions-policy": { weight: 10, good: (v) => v.length > 0 },
      "x-xss-protection": { weight: 5, good: (v) => v.startsWith("1") },
      "strict-transport-security": { weight: 15, good: (v) => v.includes("max-age") },
      "x-dns-prefetch-control": { weight: 5, good: (v) => v === "off" },
    };

    const found: Record<string, string> = {};
    const missing: string[] = [];
    const details: string[] = [];
    let score = 0;

    for (const [header, config] of Object.entries(secHeaders)) {
      const value = resp.headers.get(header);
      if (value) {
        found[header] = value;
        if (config.good(value)) {
          score += config.weight;
          details.push(`${header}: ${value.slice(0, 60)}`);
        } else {
          score += Math.floor(config.weight / 2);
          details.push(`${header}: weak value`);
        }
      } else {
        missing.push(header);
      }
    }

    if (missing.length > 0) {
      details.push(`Missing: ${missing.join(", ")}`);
    }

    // Bonus for server not revealing version
    const server = resp.headers.get("server");
    if (!server) { score += 10; details.push("Server header hidden (good)"); }
    else if (server.includes("/")) { details.push(`Server: ${server} — version exposed`); }
    else { score += 5; details.push(`Server: ${server}`); }

    // Bonus for X-Powered-By not present
    if (!resp.headers.get("x-powered-by")) { score += 10; details.push("X-Powered-By hidden (good)"); }
    else { details.push(`X-Powered-By: ${resp.headers.get("x-powered-by")} — info leak`); }

    const result: HeadersResult = { headers: found, missing, score: Math.min(100, score), details };
    setCache(cacheKey, result);
    return result;
  } catch (e: any) {
    return { headers: {}, missing: [], score: 0, details: [`Headers check failed: ${e.message}`] };
  }
}

// ─── Content / Reputation Check ─────────────────────────────────────────────

interface ContentResult {
  reachable: boolean;
  statusCode: number;
  redirects: boolean;
  hasRobotsTxt: boolean;
  latencyMs: number;
  score: number; // 0-100
  details: string[];
}

async function checkContent(domain: string): Promise<ContentResult> {
  const cacheKey = `content_${domain}`;
  const c = cached<ContentResult>(cacheKey);
  if (c) return c;

  const details: string[] = [];
  let score = 0;

  try {
    const start = Date.now();
    const resp = await fetch(`https://${domain}`, {
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    });
    const latencyMs = Date.now() - start;
    const statusCode = resp.status;
    const redirects = resp.redirected;

    if (statusCode >= 200 && statusCode < 300) { score += 30; details.push(`Status: ${statusCode} OK`); }
    else if (statusCode >= 300 && statusCode < 400) { score += 20; details.push(`Status: ${statusCode} redirect`); }
    else { details.push(`Status: ${statusCode}`); }

    if (latencyMs < 500) { score += 20; details.push(`Latency: ${latencyMs}ms (fast)`); }
    else if (latencyMs < 2000) { score += 10; details.push(`Latency: ${latencyMs}ms (ok)`); }
    else { score += 5; details.push(`Latency: ${latencyMs}ms (slow)`); }

    // Check robots.txt
    let hasRobotsTxt = false;
    try {
      const robotsResp = await fetch(`https://${domain}/robots.txt`, { signal: AbortSignal.timeout(3000) });
      hasRobotsTxt = robotsResp.ok && (await robotsResp.text()).includes("User-agent");
      if (hasRobotsTxt) { score += 10; details.push("robots.txt present"); }
    } catch {}

    // Check if response has meaningful content
    const contentLength = parseInt(resp.headers.get("content-length") || "0");
    const contentType = resp.headers.get("content-type") || "";
    if (contentType.includes("text/html") || contentType.includes("application/json")) {
      score += 15; details.push(`Content-Type: ${contentType.split(";")[0]}`);
    }

    // Check for well-known files (sign of a maintained site)
    try {
      const faviconResp = await fetch(`https://${domain}/favicon.ico`, { method: "HEAD", signal: AbortSignal.timeout(3000) });
      if (faviconResp.ok) { score += 10; details.push("Favicon present"); }
    } catch {}

    // CORS headers (sign of an API)
    if (resp.headers.get("access-control-allow-origin")) {
      score += 15; details.push("CORS configured (API-ready)");
    }

    const result: ContentResult = { reachable: true, statusCode, redirects, hasRobotsTxt, latencyMs, score: Math.min(100, score), details };
    setCache(cacheKey, result);
    return result;
  } catch (e: any) {
    return { reachable: false, statusCode: 0, redirects: false, hasRobotsTxt: false, latencyMs: -1, score: 0, details: [`Unreachable: ${e.message}`] };
  }
}

// ─── Wallet Check (EVM) ─────────────────────────────────────────────────────

interface WalletResult {
  address: string;
  balanceEth: number;
  transactionCount: number;
  isContract: boolean;
  score: number;
  details: string[];
}

async function checkWallet(address: string): Promise<WalletResult> {
  const cacheKey = `wallet_${address}`;
  const c = cached<WalletResult>(cacheKey);
  if (c) return c;

  const details: string[] = [];
  let score = 0;

  try {
    const rpc = "https://mainnet.base.org";

    // Get balance, tx count, and code in parallel
    const [balRes, txRes, codeRes] = await Promise.all([
      fetch(rpc, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "eth_getBalance", params: [address, "latest"], id: 1 }) }),
      fetch(rpc, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "eth_getTransactionCount", params: [address, "latest"], id: 2 }) }),
      fetch(rpc, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "eth_getCode", params: [address, "latest"], id: 3 }) }),
    ]);

    const balData = await balRes.json() as any;
    const txData = await txRes.json() as any;
    const codeData = await codeRes.json() as any;

    const balanceEth = parseInt(balData.result || "0", 16) / 1e18;
    const transactionCount = parseInt(txData.result || "0", 16);
    const isContract = (codeData.result || "0x") !== "0x";

    if (isContract) { score += 20; details.push("Smart contract — verified code"); }
    else { details.push("EOA (externally owned account)"); score += 10; }

    if (transactionCount > 1000) { score += 30; details.push(`${transactionCount} transactions — very active`); }
    else if (transactionCount > 100) { score += 25; details.push(`${transactionCount} transactions — active`); }
    else if (transactionCount > 10) { score += 15; details.push(`${transactionCount} transactions`); }
    else if (transactionCount > 0) { score += 5; details.push(`${transactionCount} transactions — low activity`); }
    else { details.push("0 transactions — unused wallet"); }

    if (balanceEth > 1) { score += 20; details.push(`Balance: ${balanceEth.toFixed(4)} ETH`); }
    else if (balanceEth > 0.01) { score += 15; details.push(`Balance: ${balanceEth.toFixed(4)} ETH`); }
    else if (balanceEth > 0) { score += 5; details.push(`Balance: ${balanceEth.toFixed(6)} ETH (low)`); }
    else { details.push("Zero balance"); }

    // Check USDC balance on Base
    try {
      const usdcRes = await fetch(rpc, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "eth_call", params: [{ to: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", data: `0x70a08231000000000000000000000000${address.slice(2).toLowerCase()}` }, "latest"], id: 4 }),
      });
      const usdcData = await usdcRes.json() as any;
      const usdc = parseInt(usdcData.result || "0", 16) / 1e6;
      if (usdc > 0) { score += 20; details.push(`USDC (Base): $${usdc.toFixed(2)}`); }
    } catch {}

    const result: WalletResult = { address, balanceEth, transactionCount, isContract, score: Math.min(100, score), details };
    setCache(cacheKey, result);
    return result;
  } catch (e: any) {
    return { address, balanceEth: 0, transactionCount: 0, isContract: false, score: 0, details: [`Wallet check failed: ${e.message}`] };
  }
}

// ─── Composite Score ────────────────────────────────────────────────────────

interface TrustScore {
  target: string;
  type: "domain" | "wallet" | "ip";
  compositeScore: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  verdict: "trusted" | "moderate" | "suspicious" | "dangerous";
  subscores: {
    ssl?: SSLResult;
    dns?: DNSResult;
    whois?: WHOISResult;
    headers?: HeadersResult;
    content?: ContentResult;
    wallet?: WalletResult;
  };
  timestamp: string;
  cachedFor: string;
}

async function evaluateTarget(target: string, checks: string[] = ["all"]): Promise<TrustScore> {
  const doAll = checks.includes("all") || checks.length === 0;

  if (isWallet(target)) {
    const wallet = await checkWallet(target);
    const compositeScore = wallet.score;
    return {
      target,
      type: "wallet",
      compositeScore,
      grade: scoreToGrade(compositeScore),
      verdict: scoreToVerdict(compositeScore),
      subscores: { wallet },
      timestamp: new Date().toISOString(),
      cachedFor: "5m",
    };
  }

  const domain = extractDomain(target);

  // Run all checks in parallel for speed
  const results = await Promise.all([
    (doAll || checks.includes("ssl")) ? checkSSL(domain) : null,
    (doAll || checks.includes("dns")) ? checkDNS(domain) : null,
    (doAll || checks.includes("whois")) ? checkWHOIS(domain) : null,
    (doAll || checks.includes("headers")) ? checkHeaders(domain) : null,
    (doAll || checks.includes("content")) ? checkContent(domain) : null,
  ]);

  const [ssl, dns, whois, headers, content] = results;

  // Weighted composite score
  const weights = { ssl: 25, dns: 15, whois: 25, headers: 20, content: 15 };
  let totalWeight = 0;
  let weightedSum = 0;

  if (ssl) { weightedSum += ssl.score * weights.ssl; totalWeight += weights.ssl; }
  if (dns) { weightedSum += dns.score * weights.dns; totalWeight += weights.dns; }
  if (whois) { weightedSum += whois.score * weights.whois; totalWeight += weights.whois; }
  if (headers) { weightedSum += headers.score * weights.headers; totalWeight += weights.headers; }
  if (content) { weightedSum += content.score * weights.content; totalWeight += weights.content; }

  const compositeScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

  return {
    target,
    type: isIP(domain) ? "ip" : "domain",
    compositeScore,
    grade: scoreToGrade(compositeScore),
    verdict: scoreToVerdict(compositeScore),
    subscores: {
      ...(ssl ? { ssl } : {}),
      ...(dns ? { dns } : {}),
      ...(whois ? { whois } : {}),
      ...(headers ? { headers } : {}),
      ...(content ? { content } : {}),
    },
    timestamp: new Date().toISOString(),
    cachedFor: "5m",
  };
}

function scoreToGrade(score: number): TrustScore["grade"] {
  if (score >= 90) return "A+";
  if (score >= 75) return "A";
  if (score >= 60) return "B";
  if (score >= 40) return "C";
  if (score >= 20) return "D";
  return "F";
}

function scoreToVerdict(score: number): TrustScore["verdict"] {
  if (score >= 75) return "trusted";
  if (score >= 50) return "moderate";
  if (score >= 25) return "suspicious";
  return "dangerous";
}

// ─── Routes ─────────────────────────────────────────────────────────────────

export function registerRoutes(app: Hono) {
  // Single target scoring
  app.post("/api/score", async (c) => {
    await tryRequirePayment(0.01);
    const body = await c.req.json().catch(() => null);
    if (!body?.target) {
      return c.json({ error: "Missing required field: target" }, 400);
    }

    const target: string = body.target.trim();
    const checks: string[] = body.checks || ["all"];

    if (target.length < 3 || target.length > 253) {
      return c.json({ error: "Invalid target — must be a domain, URL, wallet address, or IP" }, 400);
    }

    try {
      const result = await evaluateTarget(target, checks);
      return c.json(result);
    } catch (e: any) {
      return c.json({ error: `Trust evaluation failed: ${e.message}` }, 500);
    }
  });

  // Batch scoring
  app.post("/api/batch", async (c) => {
    await tryRequirePayment(0.02);
    const body = await c.req.json().catch(() => null);
    if (!body?.targets || !Array.isArray(body.targets)) {
      return c.json({ error: "Missing required field: targets (array of 2-5 strings)" }, 400);
    }

    const targets: string[] = body.targets.slice(0, 5);
    if (targets.length < 2) {
      return c.json({ error: "Batch requires at least 2 targets" }, 400);
    }

    try {
      const results = await Promise.all(targets.map((t) => evaluateTarget(t.trim())));

      // Sort by score descending
      results.sort((a, b) => b.compositeScore - a.compositeScore);

      return c.json({
        count: results.length,
        mostTrusted: results[0].target,
        leastTrusted: results[results.length - 1].target,
        results,
        timestamp: new Date().toISOString(),
      });
    } catch (e: any) {
      return c.json({ error: `Batch evaluation failed: ${e.message}` }, 500);
    }
  });
}
