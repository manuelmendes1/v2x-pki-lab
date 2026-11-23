# Validation gates

Use these gates in order. Record each result as PASS, FAIL or UNVERIFIED with command, revision, toolchain and evidence path.

| Gate | Required evidence | A PASS does not imply |
|---|---|---|
| G0 — layout | Lab layout and policy manifests exist | Credentials exist |
| G1 — issuer profile | Issuer binary and compile definitions prove standard ASN.1 profile | Certificates are correct |
| G2 — OER/ASN.1 | All certs decode and satisfy ASN.1 constraints | Signatures are valid |
| G3 — signatures | Root self-signature, AA-by-Root, AT-by-AA verified with OpenSSL | Root is trusted |
| G4 — issuer binding | Subject issuer digest matches exact issuer certificate | CA permissions are valid |
| G5 — chain policy | CA permission containment, assurance and validity-subset checks | AT is usable now |
| G6 — application policy | Required AIDs/SSPs explicitly present at each required level | Certificate is in date |
| G7 — time | Root, AA and AT valid for actual simulation times | Location is valid |
| G8 — region | Position, region restriction and location checker all configured and pass | Runtime signer initializes |
| G9 — trust/revocation | Explicit root trust anchor, issuer lookup and revocation policy | Message signing works |
| G10 — signer | Real production signer initializes and signs with real credential | Network transmission works |
| G11 — E2E | Protocol pipeline and receiver evidence, with per-stage counts | Other protocols pass |

## Evidence vocabulary

- `PASS`: the exact gate was executed and its assertions passed.
- `FAIL`: the gate was executed and a defined assertion failed.
- `UNVERIFIED`: missing evidence, unavailable implementation, incomplete setup or build/runtime error prevented a conclusion.

A source-code inspection is not runtime evidence. A successful OER decode is not signature verification. A valid ECC signature is not proof of authorization, validity, trust or region acceptance.
