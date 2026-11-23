# Audited baseline — 2026-11-22

## Scope

Historical fixture:

`~/final/ns-3.47/scratch/test-results/denm_pki_runtime_20261019_101645`

It was inspected read-only. This lab does not copy, rename, regenerate or modify that fixture.

## Cryptographic verification

The temporary verifier was compiled with G++ 11 against the installed Vanetza prefix:

`~/opt/vanetza-cpm-gcc11`

It selected the `OpenSSL` backend explicitly and used the standard ASN.1 profile (`VANETZA_WITH_PQC=OFF`). Results supplied on 2026-11-22:

- Root OER decode and ASN.1 constraints: PASS.
- AA OER decode and ASN.1 constraints: PASS.
- AT `veh0` OER decode and ASN.1 constraints: PASS.
- Root self-signature: `SIGNATURE_VALID`.
- AA primary signature by Root: `SIGNATURE_VALID`.
- AT `veh0` primary signature by AA: `SIGNATURE_VALID`.
- Fleet audit: 100 AT found, 100 signatures verified, 0 failures.

This proves primary ECC signature verification and issuer-digest binding for the tested chain elements. It does not by itself prove trust-store acceptance, revocation status, location/region validity or runtime signer initialization.

## Authorization and validity

Policy audit supplied on 2026-11-22:

| Object | AID 36 issuance/use | AID 37 issuance/use | Valid at 2026-10-19 reference | Valid at 2026-11-22 audit time |
|---|---:|---:|---:|---:|
| Root | 0 | 1 | 1 | 1 |
| AA | 0 | 1 | 1 | 1 |
| 100 ATs | 0/100 | 100/100 | 100/100 | 0/100 |

Summary:

- `AT_TOTAL=100`
- `AT_AID36_COUNT=0`
- `AT_AID37_COUNT=100`
- `AT_BOTH_AIDS_COUNT=0`
- `AT_VALID_AT_REFERENCE_COUNT=100`
- `AT_VALID_AT_AUDIT_DATE_COUNT=0`
- `AT_PARSE_FAIL_COUNT=0`

The recorded AT validity end was 2026-10-26 08:16:45 UTC. The original ATs are expired by the 2026-11-22 audit.

## Runtime implication

The observed signer failure is consistent with:

- CAM / AID 36: `InsufficientPermission`.
- DENM / AID 37: `Expired`.

The evidence does not justify weakening the validator or changing simulation time. A new fixture must be issued with correct CA issuance permissions, AT application permissions and a validity period covering the actual simulation.

## Toolchain caveat

The historical tool inventory showed:

- `certify` is the classic certificate utility, not an established local standard-profile V3 issuer.
- `certify-pqc --profile ecc` produced the historical ECC-only fixture. The ECC signatures were verified by the standard-profile verifier, but the tool is built within the experimental hybrid-PQC ASN.1 profile.
- `pki` is an enrolment/AT-request client for an external PKI workflow, not a standalone local Root/AA issuer.

No new certificates were generated during this audit.
