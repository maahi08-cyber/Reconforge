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
- [x] Remove proven orphan implementations

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
- [x] Capability-aware sensor planning integrated into scans
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
- [x] Ownership intelligence integrated into live hypotheses
- [x] Workflow intelligence integrated into live hypotheses
- [x] Read-only graph query CLI
- [x] JS intelligence integrated into authorized active scanner path
- [x] Temporal surface deltas integrated into scans
- [x] Canonical evidence correlation primitives
- [x] Negative-evidence signals integrated into live Hunter scoring
- [ ] Broader canonical correlation across every sensor family

## Phase 3 — Hunter Queue
- [x] Basic hypothesis generation
- [x] Persistent queue storage
- [x] Researcher feedback CLI
- [x] Persistent calibration events
- [x] Conservative calibration applied during scans
- [x] Canonical explainable Hunter Queue ranking
- [x] Queue priority/rationale persisted with hypotheses
- [x] New temporal surfaces can generate exposure-research hypotheses
- [x] Source-family corroboration integrated into Hunter
- [ ] Investigation cards wired to live queue
- [ ] Richer negative-evidence taxonomy
- [ ] Empirical cross-source diversity calibration

## Phase 4 — authorization and workflow intelligence
- [x] Authorized response/session fixture comparison
- [x] Ownership intelligence module
- [x] Workflow intelligence module
- [x] Wire ownership signals into live hypotheses
- [x] Wire workflow transition hypotheses into live hypotheses
- [x] Unified authorized differential → research hypothesis path
- [ ] Rich object ownership mapping
- [ ] Deeper workflow invariants
- [ ] Authenticated differential orchestration integrated into scans

## Phase 5 — precision engineering
- [x] Benchmark format foundation
- [x] Initial labeled benchmark cases
- [x] Precision metric implementation
- [x] Live-path regression tests
- [x] Executable benchmark runner
- [x] Executable regression runner
- [x] CI quality workflow
- [x] Correlation/negative-evidence regression contracts
- [ ] Larger independent benchmark corpus with stable labels
- [ ] Top-5 / Top-10 / Top-20 empirical measurements on stable corpus
- [ ] Duplicate/N/A rate measurement on stable corpus
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

A capability is only marked complete when it is implemented, reachable from the production CLI/orchestrator, covered by a live-path test, and supported by evidence from the validation corpus.
