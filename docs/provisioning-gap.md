# Provisioning gap and implementation boundary

## Finding

The existing tool inventory does not establish a suitable local standard-profile V3 Root/AA/AT issuer:

- `tools/certify` is the classic certificate tool.
- `tools/pki` implements enrolment and AT request workflows intended to interact with an external PKI; it is not a local self-contained authority generator.
- `tools/certify-pqc` can create ECC-only material with `--profile ecc`, but it is compiled only when `VANETZA_WITH_PQC=ON` and uses the experimental hybrid-PQC ASN.1 profile. The historical outputs nevertheless decoded and had their primary ECC signatures verified using the installed standard-profile libraries. This is useful interoperability evidence, not approval to treat the experimental-profile tool as the production standard-profile issuer.

## Required work before issuance

1. Define Root, AA and AT certificate roles and permitted issuance scopes for each trust domain.
2. Implement or identify a V3 issuer that builds against the standard ASN.1 profile (`VANETZA_WITH_PQC=OFF`).
3. Use the installed OpenSSL ECC backend; never use the Null backend for signature acceptance.
4. Generate Root -> AA -> AT and verify each primary signature with an independent verifier built against the same standard-profile runtime libraries.
5. Verify issuer digests, CA permission containment, assurance, validity subset, application permissions and geographic restrictions.
6. Validate the complete chain with the runtime validator configured with explicit trust store, issuer lookup, revocation lookup, runtime clock, position provider and location checker.
7. Run isolated signer tests and then protocol-specific end-to-end tests.

## Do not do

- Do not change production ITS time to make an expired ticket appear valid.
- Do not disable time, chain, region or location checks.
- Do not use `BackendNull`, `NullCertificateValidator` or `NaiveCertificateProvider` for acceptance.
- Do not regenerate or overwrite the historical DENM fixture.
- Do not copy private keys into Git or into another protocol directory.

Until these requirements pass, each domain manifest remains `issuance_status: blocked`.
