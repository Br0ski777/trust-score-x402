# Trust Score API

[![MCP Server](https://img.shields.io/badge/MCP-server-blue)](https://trust-score.api.klymax402.com/mcp)
[![x402](https://img.shields.io/badge/payments-x402-6E56CF)](https://x402.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Evaluate trustworthiness of any domain, URL, wallet, or API. Returns 0-100 score with 5 sub-scores: SSL, DNS, WHOIS, security headers, content. Zero-cost, zero-dependency. The trust layer agents need before interacting with unknown services. Pay-per-call via [x402](https://x402.org) (USDC on Base L2) -- no API key, no signup, no rate-limit wall.

Part of the [klymax402](https://klymax402.com) marketplace -- 100 x402 micropayment APIs for AI agents, one wallet, USDC on Base.

## Quickstart -- MCP

Add to your MCP client config (Claude Desktop, Cursor, ElizaOS, etc.):

```json
{
  "mcpServers": {
    "trust-score": {
      "url": "https://trust-score.api.klymax402.com/mcp"
    }
  }
}
```

## Quickstart -- HTTP (x402)

```bash
curl -X POST "https://trust-score.api.klymax402.com/api/score" \
  -H "Content-Type: application/json" \
  -d '{"target":"..."}'
# -> 402 Payment Required, with an x402 payment challenge in the response body
```

Any x402-aware client ([`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch), [`x402-agent-tools`](https://www.npmjs.com/package/x402-agent-tools), ATXP) handles the 402 -> sign -> retry cycle automatically.

## Tools

| Tool | Method | Path | Price | Description |
|---|---|---|---|---|
| `trust_score_evaluate` | POST | `/api/score` | $0.02 | Evaluate trust of a domain, URL, wallet address, or API endpoint. Returns composite score 0-100 with grade (A+ to F), verdict (trusted/moderate/suspicious/dangerous), and 5 detailed sub-scores. |
| `trust_score_batch_compare` | POST | `/api/batch` | $0.03 | Compare trustworthiness of 2-5 targets side by side. Returns all scores ranked from most to least trusted. |

### `trust_score_evaluate`

Use this when you need to check if a domain, website, API endpoint, or crypto wallet is safe to interact with. Returns a composite trust score 0-100 with letter grade (A+ to F), verdict (trusted/moderate/suspicious/dangerous), and 5 sub-scores:

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | yes | Domain (example.com), full URL (https://api.example.com/v1), wallet address (0x...), or IP address to evaluate |
| `checks` | array | no | Which checks to run. Default: all. Pass a subset like ["ssl","dns"] for faster results (under 2s). Full scan takes 3-8s. |

Example response:

```json
{ compositeScore: 82, grade: "A", verdict: "trusted", subscores: { ssl: { score: 90, ... }, dns: { score: 85, ... }, ... } }
```

**When to use**: making payments, sending sensitive data, or trusting any external service. Essential for agent safety.

**Not for**: SEO analysis (use `seo_audit_page`), email validation (use `email_verify_address`), tech stack detection (use `website_detect_tech_stack`), port scanning (use `network_scan_ports`).

### `trust_score_batch_compare`

Use this when you need to compare the trustworthiness of multiple domains, URLs, or wallets and pick the safest option. Accepts 2-5 targets and returns trust scores for all, sorted from most to least trusted.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `targets` | array | yes | List of 2-5 domains, URLs, or wallet addresses to evaluate and rank |

**Not for**: single targets (use `trust_score_evaluate`).

## Example agent prompts

- "Check if a domain, website, API endpoint, or crypto wallet is safe to interact with"
- "Compare the trustworthiness of multiple domains, URLs, or wallets and pick the safest option"

## Payment

- Protocol: [x402](https://x402.org) -- HTTP-native pay-per-call, no signup, no API key
- Network: Base L2 (`eip155:8453`)
- Asset: USDC
- Facilitator: Coinbase CDP (primary), PayAI (fallback)
- Also reachable via [ATXP](https://atxp.ai) (OAuth-wrapped x402, RFC 9728 protected-resource metadata)

## Part of klymax402

100 x402 micropayment APIs for AI agents -- one wallet, USDC on Base, zero signup.

- Catalog: https://klymax402.com/llms.txt
- Full API reference: https://klymax402.com/llms-full.txt
- Live stats: https://klymax402.com/stats

## License

MIT
