# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Markdown, XML, JSON e Python sem dependências externas.

## Users

Blue team analysts and detection engineers que precisam versionar, revisar e validar seu portfólio de detecções.

## Product Purpose

Version, validate and communicate Wazuh detections as code, with a safe Purple Team validation path that is separate from the laboratory infrastructure.

## Positioning

Each detection carries its engineering contract: ATT&CK mapping, quality metadata, regression fixtures, a benign validation scenario and rollback instructions.

## Operating Context

The repository is reviewed through GitHub and CI. Operational monitoring and investigation occur in Wazuh; validations occur only in isolated, authorized virtual machines.

## Capabilities and Constraints

- Rules target Wazuh and Windows telemetry.
- Wazuh remains the only operational dashboard; this repository does not duplicate it.
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
