# Architecture and protocol isolation

## Two independent axes

This lab separates:

1. **Protocol operations** — per-protocol policy, test cases, evidence and credential references under `protocols/<protocol>/`.
2. **PKI trust domains** — Root/AA hierarchy, trust anchors and revocation data under `pki/domains/<domain>/`.

A protocol folder does not automatically imply a unique Root CA. A trust domain is shared only where the project architecture and policy explicitly allow it.

## Domain allocation

| Protocol | AID / PSID | Domain | Initial status |
|---|---:|---|---|
| CAM | 36 | `vehicle-v3` | Re-provisioning required; ticket must authorize AID 36 |
| DENM | 37 | `vehicle-v3` | Re-provisioning required; current historical ATs are expired |
| CPM | 639 | `cpm-v3` | Separate domain; provisioner/fixture not yet established here |
| SPATEM | 137 | `rsu-spatem-v3` | Separate RSU domain; preserve existing RSU identity boundaries |
| VAM | 638 (current project mapping) | Unassigned | Unsupported; do not issue until source/runtime support is confirmed |

AIDs are project mappings recorded in the supplied project context; re-check them against the active source revision before issuance.

## CAM and DENM: shared vehicle domain

The current ns-3 implementation shares the vehicle V3 signer/verifier for CAM and DENM. The signer loads an active credential and checks that credential for both AID 36 and AID 37. Consequently:

- Shared Root/AA trust does not imply shared application authorization.
- A ticket authorized only for AID 37 cannot sign CAM.
- A ticket authorized only for AID 36 cannot sign DENM.
- If the current shared signer is expected to serve both protocols with one active ticket, that ticket must explicitly authorize both AIDs and the Root/AA issuance permissions must permit the relevant chain.
- If a future design uses separate per-protocol ATs, credential selection must become application-aware and be tested; directory separation alone does not implement that behavior.

The `protocols/cam/` and `protocols/denm/` folders therefore hold separate policy/evidence while the common vehicle trust chain remains in `pki/domains/vehicle-v3/`.

## CPM and SPATEM

CPM and SPATEM remain separate trust domains as required by the current project architecture. CPM uses its own domain and AID mapping; SPATEM uses an RSU-specific domain and must not reuse vehicle credentials. The project invariant remains:

`Link MAC != GN_ADDR.MID != stationId`

## VAM

The current project context marks AID 638 as unsupported. The VAM folder is a planning and evidence boundary only. It must not contain issued credentials until message security, signer/verifier integration, AID support and policy are demonstrated in the active checkout.

## Credential data flow

The intended sequence for a future fixture is:

`policy -> issuer profile -> certificate issuance -> OER decode -> issuer binding -> ECC signature verification -> chain/trust validation -> permission/time/region validation -> runtime acceptance -> protocol E2E evidence`

Passing one stage never implies the next stage passed.
