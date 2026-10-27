# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML, CSS and vanilla JavaScript generated from the detection catalog; no external runtime required.

## Users

Blue team analysts and detection engineers who need to understand the state, coverage and validation evidence of their detection portfolio.

## Product Purpose

Version, validate and communicate Wazuh detections as code, with a safe Purple Team validation path that is separate from the laboratory infrastructure.

## Positioning

Each detection carries its engineering contract: ATT&CK mapping, quality metadata, regression fixtures, a benign validation scenario and rollback instructions.

## Operating Context

The repository is reviewed through GitHub, CI and local Markdown/static dashboard files. Operational validations occur only in isolated, authorized virtual machines.

## Capabilities and Constraints

- Rules target Wazuh and Windows telemetry.
- Dashboard is retained inside the project for now; it is not published as a public site.
- Purple Team exercises are benign, documented and must not include exploitation, malware, credential collection or persistence beyond disposable test artifacts.

## Evidence on Hand

- `catalog/detections.yaml` is the source of detection metadata.
- `tests/fixtures/` contains synthetic positive and negative test events.
- `simulations/` contains benign runbooks.

## Product Principles

- Treat detections as reviewable software.
- Keep lab infrastructure and detection engineering independently auditable.
- Make validation evidence explicit and repeatable.
- Prefer safe simulation over adversary emulation.
