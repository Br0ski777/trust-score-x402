import type { ApiConfig } from "./shared.ts";

export const API_CONFIG: ApiConfig = {
  name: "Trust Score API",
  slug: "trust-score",
  description: "Evaluate trustworthiness of any domain, URL, wallet, or API. Returns 0-100 score with 5 sub-scores: SSL, DNS, WHOIS, security headers, content. Zero-cost, zero-dependency. The trust layer agents need before interacting with unknown services.",
  version: "1.0.0",
  routes: [
    {
      method: "POST",
      path: "/api/score",
      price: "$0.01",
      description: "Evaluate trust of a domain, URL, wallet address, or API endpoint. Returns composite score 0-100 with grade (A+ to F), verdict (trusted/moderate/suspicious/dangerous), and 5 detailed sub-scores.",
      toolName: "trust_score_evaluate",
      toolDescription:
        `Use this when you need to check if a domain, website, API endpoint, or crypto wallet is safe to interact with. Returns a composite trust score 0-100 with letter grade (A+ to F), verdict (trusted/moderate/suspicious/dangerous), and 5 sub-scores:

1. SSL/TLS (25%): certificate validity, HSTS, expiry, issuer
2. DNS (15%): A/AAAA/MX/NS records, SPF, DMARC, DNSSEC
3. WHOIS (25%): domain age, registrar reputation, expiry, suspicious TLDs
4. Security Headers (20%): CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy
5. Content (15%): reachability, latency, status code, robots.txt, CORS

For wallet addresses (0x...): returns on-chain trust based on transaction count, ETH/USDC balance, contract status on Base L2.

Example output: { compositeScore: 82, grade: "A", verdict: "trusted", subscores: { ssl: { score: 90, ... }, dns: { score: 85, ... }, ... } }

Use this BEFORE making payments, sending sensitive data, or trusting any external service. Essential for agent safety.

Do NOT use for SEO analysis -- use seo_audit_page instead. Do NOT use for email validation -- use email_verify_address instead. Do NOT use for tech stack detection -- use website_detect_tech_stack instead. Do NOT use for port scanning -- use network_scan_ports instead.`,
      inputSchema: {
        type: "object",
        properties: {
          target: {
            type: "string",
            description:
              "Domain (example.com), full URL (https://api.example.com/v1), wallet address (0x...), or IP address to evaluate",
          },
          checks: {
            type: "array",
            items: { type: "string", enum: ["ssl", "dns", "whois", "headers", "content", "all"] },
            description: "Which checks to run. Default: all. Pass a subset like [\"ssl\",\"dns\"] for faster results (under 2s). Full scan takes 3-8s.",
          },
        },
        required: ["target"],
      },
      outputSchema: {
        type: "object",
        properties: {
          target: { type: "string" },
          type: { type: "string", enum: ["domain", "wallet", "ip"] },
          compositeScore: { type: "number", description: "0-100 trust score" },
          grade: { type: "string", enum: ["A+", "A", "B", "C", "D", "F"] },
          verdict: { type: "string", enum: ["trusted", "moderate", "suspicious", "dangerous"] },
          subscores: {
            type: "object",
            properties: {
              ssl: { type: "object", properties: { score: { type: "number" }, grade: { type: "string" }, details: { type: "array" } } },
              dns: { type: "object", properties: { score: { type: "number" }, details: { type: "array" } } },
              whois: { type: "object", properties: { score: { type: "number" }, domainAge: { type: "number" }, registrar: { type: "string" } } },
              headers: { type: "object", properties: { score: { type: "number" }, missing: { type: "array" } } },
              content: { type: "object", properties: { score: { type: "number" }, latencyMs: { type: "number" } } },
            },
          },
          timestamp: { type: "string" },
        },
        required: ["target", "compositeScore", "grade", "verdict"],
      },
    },
    {
      method: "POST",
      path: "/api/batch",
      price: "$0.02",
      description: "Compare trustworthiness of 2-5 targets side by side. Returns all scores ranked from most to least trusted.",
      toolName: "trust_score_batch_compare",
      toolDescription:
        `Use this when you need to compare the trustworthiness of multiple domains, URLs, or wallets and pick the safest option. Accepts 2-5 targets and returns trust scores for all, sorted from most to least trusted.

Returns: { mostTrusted: "...", leastTrusted: "...", results: [{ compositeScore, grade, verdict, subscores }] }

Use cases:
- Comparing API providers before choosing one
- Verifying multiple domains from a search result
- Ranking wallet addresses by on-chain reputation
- Due diligence on a list of services

Do NOT use for single targets -- use trust_score_evaluate instead (cheaper at $0.01 vs $0.02).`,
      inputSchema: {
        type: "object",
        properties: {
          targets: {
            type: "array",
            items: { type: "string" },
            minItems: 2,
            maxItems: 5,
            description: "List of 2-5 domains, URLs, or wallet addresses to evaluate and rank",
          },
        },
        required: ["targets"],
      },
      outputSchema: {
        type: "object",
        properties: {
          count: { type: "number", description: "Number of targets evaluated" },
          mostTrusted: { type: "string", description: "Target with the highest trust score" },
          leastTrusted: { type: "string", description: "Target with the lowest trust score" },
          results: {
            type: "array",
            description: "Array of trust score results sorted by score descending",
            items: {
              type: "object",
              properties: {
                target: { type: "string" },
                compositeScore: { type: "number" },
                grade: { type: "string" },
                verdict: { type: "string" },
                subscores: { type: "object" },
              },
            },
          },
          timestamp: { type: "string", description: "ISO 8601 timestamp" },
        },
        required: ["count", "mostTrusted", "leastTrusted", "results"],
      },
    },
  ],
};
