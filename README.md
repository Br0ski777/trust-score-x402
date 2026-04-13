# Trust Score API

**Unified trust scoring for domains, wallets, and APIs. Score 0-100 with 5 sub-scores. Powered by x402 micropayments.**

The trust layer AI agents need before interacting with unknown services. One API call tells you if a domain, wallet, or endpoint is safe.

## What It Scores

| Sub-score | Weight | What it checks |
|-----------|--------|----------------|
| **SSL/TLS** | 25% | Certificate validity, HSTS, expiry, issuer, preload |
| **WHOIS** | 25% | Domain age, registrar reputation, expiry date, suspicious TLDs |
| **Security Headers** | 20% | CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy, X-Content-Type-Options |
| **DNS** | 15% | A/AAAA/MX/NS records, SPF, DMARC, DNSSEC |
| **Content** | 15% | Reachability, latency, status code, robots.txt, favicon, CORS |

For **wallet addresses** (0x...): transaction count, ETH/USDC balance, contract detection on Base L2.

## Endpoints

### `POST /api/score` - $0.01/call

Evaluate a single target.

```json
{
  "target": "example.com",
  "checks": ["all"]
}
```

Response:
```json
{
  "target": "example.com",
  "type": "domain",
  "compositeScore": 72,
  "grade": "B",
  "verdict": "moderate",
  "subscores": {
    "ssl": { "score": 90, "grade": "A+", "valid": true, "details": ["HTTPS active", "HSTS max-age=31536000 (1yr+)"] },
    "dns": { "score": 85, "details": ["2 A record(s)", "SPF configured", "DMARC configured"] },
    "whois": { "score": 60, "domainAge": 10957, "registrar": "Cloudflare, Inc.", "details": ["Domain age: 30 years"] },
    "headers": { "score": 55, "missing": ["content-security-policy", "permissions-policy"], "details": ["x-frame-options: DENY"] },
    "content": { "score": 70, "latencyMs": 234, "details": ["Status: 200 OK", "Latency: 234ms (fast)"] }
  },
  "timestamp": "2026-04-13T10:45:00.000Z",
  "cachedFor": "5m"
}
```

### `POST /api/batch` - $0.02/call

Compare 2-5 targets side by side, ranked by trust score.

```json
{
  "targets": ["google.com", "sketchy-site.tk", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"]
}
```

Response:
```json
{
  "count": 3,
  "mostTrusted": "google.com",
  "leastTrusted": "sketchy-site.tk",
  "results": [
    { "target": "google.com", "compositeScore": 82, "grade": "A", "verdict": "trusted" },
    { "target": "0xd8dA...", "compositeScore": 70, "grade": "B", "verdict": "moderate" },
    { "target": "sketchy-site.tk", "compositeScore": 15, "grade": "F", "verdict": "dangerous" }
  ]
}
```

## Grading Scale

| Score | Grade | Verdict | Meaning |
|-------|-------|---------|---------|
| 90-100 | A+ | trusted | Excellent security posture, well-established |
| 75-89 | A | trusted | Good security, minor improvements possible |
| 60-74 | B | moderate | Acceptable, some security gaps |
| 40-59 | C | moderate | Below average, multiple issues |
| 20-39 | D | suspicious | Poor security, use with caution |
| 0-19 | F | dangerous | Critical issues, avoid interaction |

## Use Cases

- **Before payments**: Check if an API or wallet is trustworthy before sending USDC
- **Agent safety**: Verify domains before scraping, crawling, or sending data
- **Due diligence**: Compare multiple service providers
- **Phishing detection**: Score suspicious URLs from emails or messages
- **Wallet vetting**: Check on-chain reputation before transacting

## MCP Integration

Works with Claude Desktop, Cursor, Copilot, and any MCP-compatible client.

```json
{
  "mcpServers": {
    "trust-score": {
      "url": "https://trust-score-production-ff18.up.railway.app/mcp",
      "transport": "sse"
    }
  }
}
```

## Payment

Uses x402 protocol. Send a request, get HTTP 402 with price, your agent signs USDC on Base automatically. No API keys, no signup.

## Related APIs

- [SSL Checker](https://ssl-checker-production-3dda.up.railway.app) - Deep SSL certificate analysis
- [DNS Lookup](https://dns-lookup-production-437a.up.railway.app) - Full DNS record query
- [Domain Intelligence](https://domain-intelligence-x402-production.up.railway.app) - WHOIS + DNS + SSL combined
- [SEO Analyzer](https://seo-analyzer-x402-production.up.railway.app) - Full SEO audit (different from trust)
- [Port Scanner](https://port-scanner-production-c3e2.up.railway.app) - Network port scanning
