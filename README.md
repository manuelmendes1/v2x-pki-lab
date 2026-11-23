# V2X PKI Lab

Standalone workspace for protocol-scoped V2X PKI policies, credential fixtures, validation and evidence.

**Initial state:** structure and policies only. No certificates, private keys, trust anchors or credentials have been generated or copied into this lab.

## Install

Extract the archive, then run:

```bash
./install.sh
```

By default this installs to `~/final/v2x-pki-lab`. An alternate destination can be supplied:

```bash
./install.sh "$HOME/labs/v2x-pki-lab"
```

The installer refuses to overwrite an existing destination. It does not modify `~/vanetza-pki-lab`, `~/final/ns-3.47`, the Vanetza installation prefix, or any existing PKI fixture.

## Layout

```text
config/
  domains/       PKI-domain metadata and permission boundaries
  protocols/     per-protocol policy manifests
pki/
  domains/       shared roots, AAs, trust stores, revocation data and issuance outputs
protocols/
  cam/           CAM-specific policy, credential references, tests and evidence
  denm/          DENM-specific policy, credential references, tests and evidence
  cpm/           CPM-specific policy, credential references, tests and evidence
  spatem/        SPATEM-specific policy, credential references, tests and evidence
  vam/           VAM scaffold; issuance blocked pending AID/runtime support
  _template/     starting point for additional protocols

docs/             architecture, security rules, baseline and validation gates
tools/            safe read-only layout and credential inventory checks
```

## PKI-domain model

Protocol directories are operational separation, not an instruction to duplicate every CA chain.

- CAM (AID 36) and DENM (AID 37) share the vehicle V3 signing/trust domain in the current ns-3 architecture. The active vehicle credential used by the shared signer must explicitly authorize every application for which it will sign. The present runtime checks both AIDs against the loaded credential; a ticket with only one AID is not dual-protocol authorization.
- SPATEM (AID 137) has a separate RSU domain.
- CPM (AID 639) has a separate domain.
- VAM (AID 638 in the current project mapping) is marked **unsupported / no issuance** until the VAM security path and AID support are confirmed in the active source tree.

See [docs/architecture.md](docs/architecture.md) and the protocol manifests under `config/`.

## Current audited baseline

The historical DENM fixture dated 2026-10-19 remains outside this lab and is not copied or modified. The audit of 2026-11-22 established:

- Root, AA and all 100 ATs decode under the installed standard ASN.1 profile.
- Root self-signature, AA signature and all 100 AT primary ECC signatures verified with the OpenSSL backend.
- Root and AA permit issuance for AID 37, not AID 36.
- All 100 ATs permit AID 37, none permit AID 36.
- All 100 ATs were valid at the 2026-10-19 reference time and expired by 2026-11-22.

That fixture is cryptographically verifiable but is not eligible for current CAM or DENM signing. Details: [docs/current-baseline.md](docs/current-baseline.md).

## Provisioning status

This scaffold intentionally does **not** generate credentials. The inventory established that:

- `certify` is the classic certificate tool, not an established local standard-profile V3 issuer.
- `certify-pqc --profile ecc` was used by the historical fixture and its ECC signatures are interoperable with the installed standard-profile verifier for the audited certificates, but it is still built within the experimental PQC ASN.1 profile.
- `pki` is the enrolment/AT-request client for an external PKI workflow, not a standalone local Root/AA issuer.

A standard-profile V3 provisioning path must be designed and tested before new credentials are issued. See [docs/provisioning-gap.md](docs/provisioning-gap.md).

## Safety rules

1. Never copy an existing private key or certificate into this scaffold automatically.
2. Never overwrite historical evidence or the original DENM fixture.
3. Keep private material outside Git; this scaffold ignores credential payload directories and common private-key formats.
4. Do not weaken validators, disable validity/region checks, substitute the Null backend, or change simulation time to make a credential pass.
5. Record the exact source revision, toolchain, ASN.1 profile, issuer chain, AIDs, validity period and verification evidence for every future fixture.

## First checks

After installation:

```bash
cd ~/final/v2x-pki-lab
./tools/validate-layout.sh
./tools/inventory-credentials.sh
```

Both commands are read-only. See [docs/validation-gates.md](docs/validation-gates.md) before adding a provisioner.
