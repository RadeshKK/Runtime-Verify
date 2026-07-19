# State Encoding & Representation

The `encoder` module maps dynamic event sequences into a mathematical or logical state space. This enables detectors to reason about complex state transitions.

## Key Concepts

- **Raw Events**: Individual, chronological observations from the telemetry stream.
- **State Window / Context**: A slicing window (by count, time, or session ID) that aggregates events.
- **Encoded State**: A representation of system state (e.g., hot-one encoding, boolean state predicates, or state machine vectors).

## State Encoder Pipelines

```
[Raw Event Stream] ──> [Filter & Clean] ──> [Feature Extraction] ──> [Vector/State Construction]
```

### Example: Predicate-Based Encoding

Map state to a set of boolean predicates evaluated over a trace window:

- `has_written_to_temp_dir`
- `is_network_active`
- `has_spawned_child`

Represented as a bitmask/vector: `[1, 0, 1]`.
