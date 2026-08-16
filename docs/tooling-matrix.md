# ReconForge Tooling Matrix

ReconForge treats external security tools as **sensors/adapters**. No adapter is allowed to bypass scope policy, normalization, provenance, correlation, or confidence gating.

## Discovery and asset intelligence

| Tool | Role | ReconForge use | High-signal outputs |
|---|---|---|---|
| Subfinder | passive subdomain discovery | broad passive coverage; source attribution per name | subdomain + source set |
| OWASP Amass | deep DNS/OSINT/attack-surface mapping | graph enrichment and relationship discovery | names, DNS, relationships, historical/change context |
| Certificate Transparency | certificate-based discovery | identify names missed by normal passive enumeration | SAN/CN names + certificate provenance |
| dnsx | DNS resolution/record interrogation | validate names and collect record observations | A/AAAA/CNAME/NS/MX/TXT/status |
| puredns / shuffledns | controlled DNS resolution/brute-force support | optional deeper validation where explicitly permitted | resolved candidates + resolver evidence |
| tlsx | TLS intelligence | correlate certificate, TLS, cipher and service observations | TLS identity/metadata |

## Network and service mapping

| Tool | Role | ReconForge use | High-signal outputs |
|---|---|---|---|
| Naabu | fast port discovery | identify exposed services before HTTP probing | host/port observations |
| Nmap | service/version/deeper port validation | targeted follow-up after high-value port discovery | service/version/script evidence |

## HTTP and web attack-surface discovery

| Tool | Role | ReconForge use | High-signal outputs |
|---|---|---|---|
| httpx | HTTP probing/fingerprinting | status, title, tech, headers, TLS and response metadata | normalized host observations |
| Katana | crawling | endpoint/route/parameter discovery including JS-aware crawling | routes, parameters, forms, assets |
| GAU | known URL aggregation | historical/passive URL enrichment | historical URLs |
| Wayback CDX / web archives | historical discovery | temporal endpoint discovery and delta analysis | first/last seen URLs |
| ffuf | controlled content discovery | targeted route discovery after evidence-based wordlist selection | discovered paths/status/size fingerprints |
| Arjun | parameter discovery | targeted parameter hypothesis generation for selected endpoints | parameter candidates |

## JavaScript and application intelligence

| Tool | Role | ReconForge use | High-signal outputs |
|---|---|---|---|
| Katana JS extraction | route/source discovery | extract routes, forms and referenced assets during crawl | endpoint references |
| jsluice | structured JS extraction | parse URLs, secrets, sinks and code references | structured JS observations |
| subjs / equivalent JS collectors | JS asset harvesting | enrich application asset inventory | JS URLs |
| Source-map analysis | client-side application intelligence | identify source references and route/schema hints when exposed | source mappings, route hints |

## Vulnerability signal layer

| Tool | Role | ReconForge use | Important rule |
|---|---|---|---|
| Nuclei | template-based detection | one corroborating sensor among many | never equals confirmed vulnerability by itself |

## ReconForge-specific intelligence

These are not wrappers around third-party tools. They are the differentiating layer:

- Scope policy engine
- Asset identity resolver
- URL/route canonicalizer
- Endpoint and parameter classifier
- Technology and version correlation
- Object/identifier detector
- Authentication-context model
- Workflow/state graph
- Evidence graph
- Historical delta engine
- Duplicate/known-noise suppression
- Negative-evidence engine
- Explainable confidence scorer
- Hunter Queue
- Researcher feedback loop
- Benchmark/evaluation harness

## Capability usage policy

### Use the best tool for the question

ReconForge should not invoke every tool on every target. The orchestrator selects sensors based on target state and missing evidence.

Example:

```text
subfinder + CT
      ↓
new candidate names
      ↓
dnsx
      ↓
resolved hosts
      ↓
httpx
      ↓
web services
      ↓
Katana + archives
      ↓
endpoints
      ↓
JS intelligence
      ↓
route/object/parameter graph
      ↓
Hunter Queue
```

### Do not stack redundant tools blindly

Multiple DNS enumerators can produce massive duplication. The value comes from **source diversity and agreement**, not simply the number of tools.

### Preserve provenance

Every observation must record:

- adapter/tool
- exact command/profile identifier
- tool version when available
- collection timestamp
- target/scope identity
- source confidence
- raw evidence reference or digest
- parser version

### Prefer machine-readable output

Adapters should use JSON/structured output where a tool supports it. Text parsing is a compatibility fallback, not the primary interface.

### Rate limiting is a security feature

The orchestrator must enforce:

- per-target request budgets
- concurrency limits
- delay/jitter profiles where appropriate
- retry budgets
- DNS/HTTP/tool-specific rate limits
- explicit opt-in for intrusive techniques

### Active testing gate

Passive evidence may automatically enrich the graph. Active content discovery, crawling, port scanning, parameter discovery and other network activity must pass the configured scope and activity policy first.

## Tool lifecycle

Each adapter has four phases:

```text
DISCOVER capability
      ↓
COLLECT observation
      ↓
NORMALIZE + CORRELATE
      ↓
FEEDBACK effectiveness
```

Effectiveness metrics are tracked per adapter so ReconForge can learn which sensors actually improve top-N research precision for different target classes.
