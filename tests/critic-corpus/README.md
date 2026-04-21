# AETERNA Critic Corpus (v0.2.0 "Custos")

This directory serves as the public test vector for the Santuario's axiomatic Critic loop, introduced in the v0.2.0 "Custos" sprint.

## Corpus Structure

The test vectors are originally located under `santuario/critic/tests/corpus/` and are divided into two main categories:

1. **Clean (`clean/`)**: 50 valid JSON payloads that fully comply with AGP-v1 schema, the ETHICS.md Prometheus Clause, and have correct signatures/hashes. The Critic must accept 100% of these.
2. **Poisoned (`poisoned/`)**: 50 adversarial payloads designed to trigger one of the three Critic axioms. The Critic must reject 100% of these.

### Axiom Violations

The poisoned payloads test the three pillars of the Cognitive Trivium:

- `rx-*` (Reflexive Violation): Payload hashes do not match the content, or the content was mutated after hashing.
- `sx-*` (Symbolic Violation): Malformed parameters, wrong protocol versions, missing fields, or invalid arrays violating the AGP-v1 schema.
- `ax-*` (Axiomatic Violation): Semantic content violating the Prometheus Clause (e.g., autonomous weapons, lethal targeting, mass surveillance, or disabling the axiom itself).

## Usage

To run the Critic test suite, invoke the cargo test runner from the `santuario/critic` directory:

```bash
cd santuario/critic
cargo test --test corpus
```

Ensure all tests pass before deploying a Sentinel node to the network.
