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
- [x] Canonical adapter contract
- [x] Explicit execution policy
- [x] Live scope enforcement
- [x] Audit/event trail foundation
- [x] Release-readiness gate

## Phase 1 — reconnaissance fabric
- [x] Run orchestration
- [x] Resumable scan execution
- [x] Process runner
- [x] Subfinder adapter
- [x] DNSx adapter
- [x] HTTPX adapter
- [x] Katana adapter
- [x] GAU adapter
- [x] Wayback adapter
- [x] Naabu adapter
- [x] Nmap enrichment adapter
- [x] JSONL observation import/export foundation
- [x] Focused FFUF adapter foundation
- [x] Focused Arjun adapter foundation
- [ ] Adapter result normalization across every sensor
- [ ] Full end-to-end validation with every external tool installed

## Phase 2 — intelligence core
- [x] Graph-backed asset identity foundation
- [x] Stable host/endpoint identity resolution
- [x] API/GraphQL endpoint classifier
- [x] Object/identifier extraction foundation
- [x] JavaScript route intelligence CLI
- [x] Client-side sensitive-data leak detection
- [x] Historical/current delta normalization
- [x] Evidence deduplication
- [x] Content-addressed evidence identity
- [ ] Integrate JS intelligence into scanner observations
- [ ] Integrate ownership intelligence into scanner observations
- [ ] Integrate workflow intelligence into scanner observations
- [ ] Cross-source correlation as a canonical live stage

## Phase 3 — Hunter Queue
- [x] Basic hypothesis generation
- [x] Persistent queue storage
- [x] Researcher feedback CLI
- [x] Persistent calibration events
- [x] Conservative calibration applied during scans
- [ ] Canonical explainable Hunter Queue ranking
- [ ] Investigation cards wired to live queue
- [ ] Evidence-quality/negative-evidence scoring in live ranking
- [ ] Cross-source diversity scoring in live ranking

## Phase 4 — authorization and workflow intelligence
- [x] Authorized response/session fixture comparison
- [x] Ownership intelligence module
- [x] Workflow intelligence module
- [ ] Wire ownership signals into live hypotheses
- [ ] Wire workflow transition hypotheses into live hypotheses
- [ ] Rich object ownership mapping
- [ ] Deeper workflow invariants

## Phase 5 — precision engineering
- [x] Benchmark format foundation
- [x] Initial regression cases
- [x] Precision metric implementation
- [x] Live-path regression tests
- [ ] Executable benchmark corpus with independent labels
- [ ] Executable false-positive regression suite
- [ ] Top-5 / Top-10 / Top-20 empirical measurements
- [ ] Duplicate/N/A rate measurement
- [ ] Per-application-family calibration

## Phase 6 — enterprise research platform
- [x] Evidence graph foundation
- [x] Read-only graph query foundation
- [x] Content-addressed evidence store
- [x] Audit/event foundation
- [x] Resumable checkpoint storage
- [x] Capability/cost/risk metadata
- [ ] Persistent graph backend
- [ ] Distributed worker backend
- [ ] Web researcher dashboard
- [ ] Optional external intelligence providers

## Release gate

ReconForge must not be called production-ready until the live CLI path passes scope enforcement, provenance, deduplication, secret redaction, resumability, executable regression coverage, and empirical precision measurement together. The project does not claim a universal vulnerability success percentage.

## Current development rule

A capability is only marked complete when it is both implemented and reachable from the production CLI/orchestrator, covered by a live-path test, and supported by evidence from the validation corpus.
