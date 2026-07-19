# Project Development Roadmap

This roadmap documents the 15 sequential phases of the `runtimeverify` framework, mapping core infrastructure, statistical algorithms, integrations, and user interfaces.

---

## Completed Phases

* **Phase 1: Event System:** Common structured telemetry event schemas (Tool, LLM, Filesystem, Network).
* **Phase 2: Telemetry Collection SDK:** Global event bus, thread-safe publishers, and decorator hook proxies.
* **Phase 3: State Representation:** Semantic state hierarchies and taxonomic categories.
* **Phase 4: State Encoder:** Pipeline matching normalizers, classifiers, and cache blocks.
* **Phase 5: Detector API:** Abstract Base Detector contracts, result models, and schema validation.
* **Phase 6: Runtime Engine:** Thread-isolated orchestration layers and dispatcher loops.
* **Phase 7: Markov Behavior Model:** First-order Markov chain matrices, transition counting, Laplace smoothing, and state distribution explainers.
* **Phase 8: SPRT Engine:** Streaming Sequential Probability Ratio Test log-likelihood accumulator and plural alternative hypothesis models ($Q$).
* **Phase 9: Evaluation Framework:** Confusion matrix metrics, synthetic event generators, replay runners, and benchmark coordinators.
* **Phase 10: Developer CLI:** Typer command-line tool `verify` (init, train, monitor, explain, doctor, version) with dynamic sub-command entrypoint discovery.
* **Phase 11: Framework Integrations:** Telemetry wrappers for LangGraph nodes, PydanticAI agents, and CrewAI task callbacks.
* **Phase 12: REST API:** FastAPI endpoints exposing health checks, metrics summaries, model training, and telemetry ingestion routes.
* **Phase 13: Observability Dashboard:** HTML5 dark-mode user monitor served directly by FastAPI, plotting live SPRT timelines and alert metrics.
* **Phase 14: VS Code Extension Stub:** Scaffolds view containers, sidebar session lists, and inspect triggers.
* **Phase 15: Cloud Service SDK:** Remote Cloud client pushing local verification alerts asynchronously.

---

## Future Extensions

* **Phase 16: Advanced Detectors:** Higher-order Markov models, Hidden Markov Models (HMM), and Bayesian Change Point detection.
* **Phase 17: Multi-Agent Topology Tracking:** Graph execution flow monitoring across distributed agent networks.
