import type { ApiConfig } from "./shared.ts";

export const API_CONFIG: ApiConfig = {
  name: "trust-score",
  slug: "trust-score",
  description: "Unified trust scoring for domains, wallets, and APIs — SSL, WHOIS, DNS, headers, content analysis",
  version: "1.0.0",
  routes: [
    {
      method: "POST",
      path: "/api/score",
      price: "$0.01",
      description: "Full trust score for a domain, URL, wallet, or API endpoint — returns 0-100 composite with sub-scores",
      toolName: "trust_score_evaluate",
      toolDescription:
        "Use this when you need to evaluate the trustworthiness of a domain, website, API endpoint, or crypto wallet address before interacting with it. Returns a composite score 0-100 with sub-scores for SSL/TLS, DNS health, domain age/reputation, security headers, and content signals. Use this BEFORE making payments, sending data, or trusting any external service. Do NOT use for SEO analysis — use seo_audit_page instead. Do NOT use for email validation — use email_verify_address instead. Do NOT use for tech stack detection — use website_detect_tech_stack instead.",
      inputSchema: {
        type: "object",
        properties: {
          target: {
            type: "string",
            description:
              "Domain (example.com), full URL (https://example.com/api), wallet address (0x...), or IP address to evaluate",
          },
          checks: {
            type: "array",
            items: { type: "string", enum: ["ssl", "dns", "whois", "headers", "content", "all"] },
            description: "Which checks to run. Default: all. Use subset for faster results.",
          },
        },
        required: ["target"],
      },
    },
    {
      method: "POST",
      path: "/api/batch",
      price: "$0.02",
      description: "Batch trust scoring — evaluate up to 5 targets at once",
      toolName: "trust_score_batch",
      toolDescription:
        "Use this when you need to compare trustworthiness of multiple domains, URLs, or wallets side by side. Accepts 2-5 targets and returns scores for all. Useful for choosing the most trustworthy option from a list. Do NOT use for single targets — use trust_score_evaluate instead.",
      inputSchema: {
        type: "object",
        properties: {
          targets: {
            type: "array",
            items: { type: "string" },
            minItems: 2,
            maxItems: 5,
            description: "List of domains, URLs, or wallet addresses to evaluate (2-5)",
          },
        },
        required: ["targets"],
      },
    },
  ],
};
