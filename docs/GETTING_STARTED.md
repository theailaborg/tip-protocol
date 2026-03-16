# Getting Started with TIP Protocol

This guide takes you from zero to a working TIP Protocol integration in the
fastest path for your use case.

---

## Choose Your Integration Path

| You want to... | Path | Time |
|---------------|------|------|
| Display trust info on your website | [HTTP Headers (Tier 0)](#tier-0-http-headers) | 5 min |
| Add per-article provenance | [HTML Meta Tags (Tier 1)](#tier-1-html-meta-tags) | 10 min |
| Embed TIP badges on pages | [Badge Widget (Tier 2)](#tier-2-badge-widget) | 30 min |
| Verify identities in your app | [SDK Integration (Tier 4)](#tier-4-sdk) | 1-5 days |
| Run your own TIP node | [Run a Node (Tier 5)](#tier-5-run-a-node) | 1-2 weeks |
| Issue verified identities | [VP Accreditation](./VP_ACCREDITATION.md) | 4-8 weeks |

---

## Tier 0: HTTP Headers

The fastest integration. Add five lines to your web server configuration.
No SDK, no JavaScript, no account required.

### Nginx

```nginx
# In your server {} or location {} block:
add_header TIP-Author        "tip://id/US-a3f8c91b2d4e7021";
add_header TIP-Content       "tip://c/OH-7f2a91bc3d5e4a-a3f8";
add_header TIP-Origin        "original-human";
add_header TIP-Trust-Score   "892";
add_header TIP-Signature     "[ML-DSA-65 signature hex]";
add_header X-Powered-By      "TIP-Protocol/theailab.org";
```

### Apache

```apache
# In your .htaccess or VirtualHost:
Header set TIP-Author      "tip://id/US-a3f8c91b2d4e7021"
Header set TIP-Content     "tip://c/OH-7f2a91bc3d5e4a-a3f8"
Header set TIP-Origin      "original-human"
Header set TIP-Trust-Score "892"
Header set X-Powered-By    "TIP-Protocol/theailab.org"
```

### Cloudflare Worker

```javascript
export default {
  async fetch(request, env) {
    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);
    newHeaders.set("TIP-Author",      "tip://id/US-a3f8c91b2d4e7021");
    newHeaders.set("TIP-Origin",      "original-human");
    newHeaders.set("TIP-Trust-Score", "892");
    return new Response(response.body, { ...response, headers: newHeaders });
  }
}
```

---

## Tier 1: HTML Meta Tags

Add TIP provenance tags to individual pages. These power browser extensions,
search engine integration, and social media previews.

```html
<head>
  <!-- Existing tags -->
  <title>Your Article Title</title>

  <!-- TIP Protocol provenance tags -->
  <meta property="tip:author"    content="tip://id/US-a3f8c91b2d4e7021" />
  <meta property="tip:content"   content="tip://c/OH-7f2a91bc3d5e4a-a3f8" />
  <meta property="tip:origin"    content="original-human" />
  <meta property="tip:score"     content="892" />
  <meta property="tip:tier"      content="HIGHLY_TRUSTED" />
  <meta property="tip:status"    content="VERIFIED" />
  <meta property="tip:node"      content="https://your-node.example.com" />
</head>
```

---

## Tier 2: Badge Widget

Drop-in badge rendering with zero configuration. The widget auto-reads
the page's TIP meta tags.

```html
<!-- Load once in your <head> or before </body> -->
<script src="https://badge.theailab.org/tip-badge.min.js" defer></script>

<!-- Render the full AI Trust ID Seal (requires a valid TIP-ID): -->
<tip-badge tip-id="tip://id/US-a3f8c91b" size="120" variant="gold-dark"></tip-badge>

<!-- Render the TIP Powered Mark (for any platform implementing TIP): -->
<tip-badge type="mark" size="80" variant="light"></tip-badge>

<!-- Auto-scan mode: reads tip:author from the page's meta tags: -->
<tip-badge auto size="80"></tip-badge>

<!-- Inline shield only (compact, good for bylines): -->
<tip-badge type="shield" tip-id="tip://id/US-a3f8c91b" size="32"></tip-badge>
```

**Attributes:**
| Attribute | Values | Default | Description |
|-----------|--------|---------|-------------|
| `tip-id` | TIP-ID URI |: | The identity to display |
| `type` | `seal` \| `mark` \| `shield` | `seal` | Badge type |
| `size` | 16-400 | 80 | Size in pixels |
| `variant` | `gold-dark` \| `light` \| `dark` | `gold-dark` | Colorway |
| `auto` | (flag) |: | Auto-scan page meta tags |

---

## Tier 4: SDK

### Installation

```bash
# Node.js
npm install @tip-protocol/sdk

# Python
pip install tip-protocol-sdk
```

### JavaScript SDK Quick Start

```javascript
const TIPClient = require("@tip-protocol/sdk");

const client = new TIPClient({
  nodeUrl: "https://node.theailab.org",
  // For write operations, provide your TIP-ID keypair:
  // privateKey: process.env.TIP_PRIVATE_KEY,
  // tipId: process.env.TIP_ID,
});

// Resolve an identity
const identity = await client.identity.resolve("tip://id/US-a3f8c91b2d4e7021");
console.log(identity.score);  // 892
console.log(identity.tier.label);  // "HIGHLY_TRUSTED"

// Register content
const record = await client.content.register({
  originCode: "OH",
  content:    "My original article text...",
  title:      "My Article",
});
console.log(record.ctid);  // "tip://c/OH-..."

// File a dispute
await client.content.dispute("tip://c/OH-7f2a91bc3d5e4a-a3f8", {
  reason:        "AI classifier flagged this as probable AI content",
  evidenceHash:  await client.crypto.shake256(classifierOutput),
});
```

### Python SDK Quick Start

```python
from tip_protocol_sdk import TIPClient

client = TIPClient(node_url="https://node.theailab.org")

# Resolve an identity
identity = client.identity.resolve("tip://id/US-a3f8c91b2d4e7021")
print(identity["score"])        # 892
print(identity["tier"]["label"])  # "HIGHLY_TRUSTED"

# Register content
record = client.content.register(
    origin_code="OH",
    content="My original article text...",
    title="My Article"
)
print(record["ctid"])  # "tip://c/OH-..."
```

---

## Tier 5: Run a Node

Running your own node gives you full independence, the ability to become a VP,
and participation in the federated network.

### Prerequisites

- Node.js 18+ or Python 3.11+
- A domain name with TLS
- At least 20GB disk for the growing DAG
- Open ports: 4000 (REST API), 4001 (gossip)

### Node.js Node

```bash
git clone https://github.com/theailab/tip-protocol.git
cd tip-protocol

# Install dependencies
npm install

# Configure
cp .env.example .env
# Edit .env:
#   TIP_JWT_SECRET=<random 256-bit hex>
#   TIP_ADMIN_API_KEY=<random 256-bit hex>
#   TIP_BOOTSTRAP_PEERS=node1.theailab.org:4001,node2.theailab.org:4001
#   TIP_GENESIS_HASH=<mainnet genesis hash: see theailab.org/genesis>

# Start
npm start
```

Your node will connect to the bootstrap peers, sync the DAG, and begin
participating in the network within a few minutes.

### Python Node

```bash
cd python
pip install -r requirements.txt

cp .env.example .env
# Edit .env as above

python -m tip_node.main
```

### Verify Your Node

```bash
curl http://localhost:4000/health
# {"status":"ok","chain_id":"tip-mainnet-v2",...}

curl http://localhost:4000/v1/node/peers
# {"peers":["node1.theailab.org:4001",...]}
```

---

## Attribution Requirement

All implementations using TIP Protocol code must display the following
attribution (see [LICENSE.txt](../LICENSE.txt) Section 4):

```html
<footer>
  Built on TIP Protocol by
  <a href="https://theailab.org">The AI Lab Intelligence Unobscured, Inc.</a>
  | Licensed under TIPCL-1.0
</footer>
```

Or use the TIP Powered Mark badge widget.

---

## Next Steps

- [Full API Reference](./API.md)
- [VP Accreditation Guide](./VP_ACCREDITATION.md)
- [GDPR Compliance Guide](./GDPR_COMPLIANCE.md)
- [Protocol Specification](../spec/TIP_Protocol_Specification_v4.0.md)
- [Commercial Licensing](https://theailab.org/licensing)

---

*Copyright 2026 The AI Lab Intelligence Unobscured, Inc. | TIPCL-1.0*
