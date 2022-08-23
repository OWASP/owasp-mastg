# Testing Resources (Assets/Observations)

Based on [OSCAL Definitions](https://pages.nist.gov/OSCAL/reference/latest/assessment-results/json-definitions/).

https://pages.nist.gov/OSCAL/presentations/oscal-ap-ar-poam-v3.pdf

These are things we can observe/inspect and derive evidence from.

Example: search sensitive data in the app container.

- Found "user PII" in cleartext in app container.
  - Observation: the list app container elements.
  - Evidence: the specific PII elements and their location.

- Found "user PII" in over IPC.
  - Observation: the list IPC calls, e.g. method trace incl. params.
  - Evidence: the specific method trace elements and the found PII.

## App Package

## App Container

## App External Storage

## Keychain

## Keystore

## Network Trace

## App Log file

## System Logs

## Method Trace

## Layout Definitions
