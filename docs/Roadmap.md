# Project Roadmap

This document details the completed, current, and future milestones for the `runtimeverify` framework.

---

## 🗺️ Current Phased Progression

```mermaid
gantt
    title Project Implementation Roadmap
    dateFormat  YYYY-MM
    section Completed
    Phase 0: Documentation       :done, p0, 2026-07, 1d
    Phase 1: Event System         :done, p1, 2026-07, 1d
    Phase 2: Telemetry SDK        :done, p2, 2026-07, 1d
    Phase 3: State Abstraction    :done, p3, 2026-07, 1d
    Phase 4: State Encoder        :done, p4, 2026-07, 1d
    Phase 5: Detector API         :done, p5, 2026-07, 1d
    Phase 6: Runtime Pipeline     :done, p6, 2026-07, 1d
    Phase 7: Markov Behavior Model:done, p7, 2026-07, 1d
    Phase 8: SPRT Engine         :done, p8, 2026-07, 1d
    section Current Phase
    Phase 9: Evaluation Framework :active, p9, 2026-07, 3d
    section Future Phases
    Phase 10: Policy Engine       :      p10, 2026-08, 5d
    Phase 11: CLI Tooling         :      p11, 2026-08, 4d
    Phase 12: Integrations        :      p12, 2026-09, 7d
    Phase 13: Dashboard           :      p13, 2026-09, 10d
```

---

## ✅ Completed Milestones

### Phase 0: Documentation
- [x] Initial design specifications, principles, and high-level architectural overview.

### Phase 1: Event System
- [x] Design framework-agnostic Event model hierarchy using Pydantic v2.
- [x] Implement specialized events (`ToolEvent`, `LLMEvent`, `MemoryEvent`, `FilesystemEvent`, `NetworkEvent`).
- [x] Set up unit tests covering event validation and immutability.

### Phase 2: Telemetry SDK
- [x] Create active `TelemetryContext` and contextvars-based propagation.
- [x] Implement thread-safe in-process `EventBus` and `TelemetryEmitter`.
- [x] Design `@observe_tool` and `@observe_llm` decorators for sync and async execution monitoring.
- [x] Implement `span` context manager for generic latency/metric tracing.
- [x] Standardize OTLP-compatible `EventSerializer`.

### Phase 3: State Abstraction
- [x] Design standard `ExecutionState` and `StateCategory` schemas.
- [x] Create taxonomous `StateHierarchy` traversing methods (`parent()`, `level()`, `is_descendant_of()`).
- [x] Implement `StateContext` to record target resources and session linkage.
- [x] Set up case-insensitive `StateRegistry` lookup maps.

### Phase 4: State Encoder
- [x] Establish modular stages: `Normalizer -> Cache Check -> Classifier -> Context Enricher -> Rule Engine -> ExecutionState`.
- [x] Implement size-limited classification `StateEncoderCache`.
- [x] Add **State Versioning** and **Provenance** (linking rule triggers and resource evidence).

### Phase 5: Detector API
- [x] Standardize the `BaseDetector` interface contract, separate from runtime and policy rules.
- [x] Define `DetectorResult` and `DetectorExplanation` payload schemas.

### Phase 6: Runtime Pipeline
- [x] Implement sequential execution loop (`Receive -> Validate -> Encode -> Dispatch -> Policy -> Publish -> Persist`).
- [x] Add **Fault Isolation** to the `Dispatcher` to prevent individual detector crashes from halting agent execution.
- [x] Establish thread-safe isolated `SessionManager` trace histories.

### Phase 7: Markov Behavior Model
- [x] Decouple transition counts, probability matrix updates, predictor scoring, metrics (entropy/sparsity), and serialization.
- [x] Support Laplace smoothing parameters to prevent zero-probability underflows on unseen transitions.

### Phase 8: Sequential Probability Ratio Test (SPRT)
- [x] Implement Wald sequential boundaries and log-likelihood accumulations.
- [x] Secure numerical stability boundaries (floating-point floors, log-domain computations, log-infinity caps).
- [x] Validate mathematical FPR/FNR rates using synthetic corpus traces.

---

## 🚀 Current & Upcoming Milestones

### Phase 9: Evaluation & Benchmarking Framework (Current Focus)
- [ ] **Simulated Corpus Generators:** Create standard synthetic trace profile logs (RAG agent, SQL writer, Coding expert) with injectible anomaly deviations.
- [ ] **Metric Aggregator:** Compare accuracy (True Positive Rate, False Positive Rate), detection speed (average observations to crossing thresholds), latency, and memory across multiple detector models.
- [ ] **Lossless Evaluation Loader:** Load trace sequences from standard JSON formats and feed them into parallel test channels.

### Phase 10: Policy Engine & Guardrails
- [ ] Implement declarative threshold policy rules matching deviation log-likelihoods.
- [ ] Design structural invariant logic (Linear Temporal Logic) to intercept forbidden actions.
- [ ] Create block mechanisms (`PolicyViolationError` exceptions) and human-in-the-loop thread suspend handles (`PAUSE` hook).

### Phase 11: CLI Tooling
- [ ] Build typer-based CLI (`runtimeverify train --logs ./logs --output model.json`).
- [ ] Implement live log monitoring commands (`runtimeverify observe --model model.json --port 8080`).

### Phase 12: Framework Integrations
- [ ] Release native node interceptor wrappers for LangGraph.
- [ ] Integrate with PydanticAI telemetry loops.

### Phase 13: Observability Dashboard
- [ ] Create a React/Vite web UI displaying live state transitions, LLR charts, anomaly alerts, and active policy violations.
