# ReconForge roadmap

The roadmap is ordered around researcher value, precision, and enterprise reliability—not feature count.

## Phase 0 — foundation
- [x] Separate repository and project identity
- [x] Stable observation model
- [x] Hypothesis/evidence model
- [x] Deterministic URL normalization
- [x] Conservative semantic classifier
- [x] Explainable confidence scoring
- [x] SQLite storage boundary
- [x] Tooling strategy and adapter contract
- [x] Explicit execution policy
- [x] Auditable run manifests

## Phase 1 — reconnaissance fabric
- [x] Scope policy engine
- [x] Run orchestration foundation
- [x] Adapter interface and process runner
- [x] Subfinder adapter
- [x] DNSx adapter
- [x] HTTPX adapter
- [x] Katana adapter
- [x] GAU adapter
- [x] Wayback adapter
- [x] Naabu adapter
- [x] Nmap enrichment adapter
- [x] JSONL observation import/export
- [x] Focused FFUF adapter foundation
- [x] Focused Arjun adapter foundation
- [ ] Adapter result normalization improvements

## Phase 2 — intelligence core
- [x] Graph-backed asset identity
- [x] Stable host/endpoint identity resolution
- [x] Technology and service observations
- [x] API/GraphQL classifier
- [x] Object/identifier extraction
- [x] Ownership-boundary signal extraction
- [x] JavaScript route intelligence
- [x] Client-side sensitive-data leak detection
- [x] Contextual leak correlation
- [x] Parameter taxonomy
- [x] Historical-to-current delta analysis
- [x] Cross-source provenance correlation
- [x] Evidence-quality and negative-evidence foundations
- [x] Temporal asset change model
- [x] Bundle/source-map provenance foundation

## Phase 3 — Hunter Queue
- [x] Explainable queue ranking
- [x] Investigation-card foundation
- [x] Recommended manual questions
- [x] Evidence and caveat display
- [x] Duplicate/source suppression
- [x] Confidence model
- [x] Researcher feedback calibration foundation
- [x] Queue precision evaluator
- [x] Calibration persistence layer
- [x] Evidence-aware sensor planner
- [ ] Persistent feedback wired into live ranking

## Phase 4 — authorization and workflow intelligence
- [x] Authorized response/session fixture comparison
- [x] Role and identity context model
- [x] Object/reference ownership signals
- [x] Workflow family extraction
- [x] Workflow state graph foundation
- [x] Business-logic transition hypotheses foundation
- [x] Authorization inconsistency signals
- [ ] Rich object ownership mapping
- [ ] Deeper workflow invariants

## Phase 5 — precision engineering
- [x] Benchmark format and evaluation metrics
- [x] Initial labeled benchmark cases
- [x] Benchmark quality reporting
- [x] False-positive regression corpus guidance
- [ ] Top-5 / Top-10 / Top-20 empirical measurements on stable corpus
- [ ] Duplicate/N/A rate measurement on stable corpus
- [x] Researcher feedback labels
- [x] Score calibration foundation
- [ ] Executable false-positive regression corpus
- [ ] Per-application-family calibration

## Phase 6 — enterprise research platform
- [x] Read-only evidence graph query layer
- [x] Persistent research graph foundation
- [x] Audit/event journal foundation
- [x] Resumable checkpoint storage
- [x] Capability/cost/risk-aware sensor planner
- [x] Content-addressed evidence store
- [ ] Durable resumable orchestration integrated into scanner
- [ ] Distributed workers
- [ ] Web dashboard
- [ ] Optional external intelligence providers

## Enterprise release-quality gates

A research-grade release must maintain scope enforcement, evidence provenance, deduplication, regression coverage, precision measurement, auditability, secret redaction, and resumability. ReconForge reports measured results rather than claiming a universal vulnerability success percentage.

## Performance objective

Every mature release should report:

- top-5 / top-10 / top-20 investigation precision
- false-positive rate
- duplicate rate
- N/A rate
- mean time to useful hypothesis
- percentage of queue items accepted as worth manual investigation
- signal-family utility over time
- collection cost per accepted hypothesis
