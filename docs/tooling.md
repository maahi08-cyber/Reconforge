# ReconForge Tooling Strategy

ReconForge treats external security tools as specialized sensors. Each sensor is selected because it contributes a distinct class of evidence; its output is normalized before entering the intelligence graph.

## Discovery and asset identity

| Sensor | Primary capability | Best use in ReconForge | Anti-noise rule |
|---|---|---|---|
| OWASP Amass | deep DNS/ASN/relationship discovery | asset graph enrichment and ownership/relationship clues | repeated aliases do not increase confidence |
| Subfinder | fast passive subdomain discovery | broad passive seed generation | passive source agreement is correlated |
| CT sources | certificate transparency | discovering forgotten/adjacent names | certificate reuse is identity evidence, not proof of ownership |
| dnsx | DNS resolution/record intelligence | resolve candidates and collect DNS evidence | NXDOMAIN/unresolved candidates are retained as negative evidence |
| puredns/shuffledns | large-scale DNS validation | validating large candidate sets | only feed validated names downstream |
| tlsx | TLS metadata/certificates | certificate/service identity enrichment | certificate fields are provenance-tagged |

## Host and service discovery

| Sensor | Primary capability | Best use | Anti-noise rule |
|---|---|---|---|
| httpx | HTTP probing/fingerprinting | identify live web services and HTTP metadata | response similarity used for deduplication |
| Naabu | fast port discovery | identify exposed network services | port alone never creates a security hypothesis |
| Nmap | service/version/scripted enumeration | deep service confirmation after candidate filtering | run selectively; expensive probes require evidence |

## URL and application surface discovery

| Sensor | Primary capability | Best use | Anti-noise rule |
|---|---|---|---|
| Katana | crawling and endpoint discovery | authenticated/unauthenticated route discovery where authorized | canonicalize routes before scoring |
| GAU | passive URL aggregation | historical/current URL seeds | source provenance preserved per URL |
| Wayback/CDX | historical URL data | historical delta and retired-route intelligence | historical existence != current exposure |
| ffuf | controlled content discovery | focused route/parameter expansion | only run on high-value hosts or explicitly authorized paths |
| Arjun | parameter discovery | identify hidden/query/body parameter candidates | candidates require endpoint/context correlation |

## Code and client-side intelligence

| Sensor | Primary capability | Best use | Anti-noise rule |
|---|---|---|---|
| jsluice | JS extraction/secrets/URLs | structured JavaScript intelligence | extracted strings are classified before scoring |
| JS/source-map analysis | route and bundle intelligence | map client code to API surfaces | duplicate route references collapse into one observation |

## Detection

| Sensor | Primary capability | Best use | Anti-noise rule |
|---|---|---|---|
| Nuclei | template-based detection | one signal source for known exposures/misconfigurations | template hits never equal confirmed vulnerability; require corroboration |

## ReconForge-native capabilities

- asset identity resolution
- URL canonicalization
- endpoint and parameter classification
- object/reference detection
- authentication/context tagging
- workflow/state modeling
- historical delta analysis
- multi-source correlation
- independent-evidence accounting
- negative-evidence penalties
- hypothesis generation
- confidence calibration
- Hunter Queue ranking
- duplicate clustering
- validation feedback

## Execution policy

1. Start passive and cheap.
2. Resolve and deduplicate before deeper probes.
3. Escalate only when evidence justifies the cost.
4. Preserve tool output provenance and command/configuration metadata.
5. Never allow multiple tools rediscovering the same fact to masquerade as independent confirmation.
6. Respect explicit scope, rate limits, authentication boundaries, and program rules.
7. Keep destructive or exploitative behavior outside the default recon pipeline.
