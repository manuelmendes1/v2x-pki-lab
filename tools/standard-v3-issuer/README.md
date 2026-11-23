# Standard-profile V3 vehicle issuer

This executable creates an isolated local ETSI TS 103 097 V3 ECC chain for the
`vehicle-v3` domain. It is deliberately separate from `certify` (V2) and
`certify-pqc` (experimental ASN.1 profile).

## Security boundary

- Compile against the installed Vanetza **standard** ASN.1 profile with
  `VANETZA_WITH_PQC=OFF`.
- Uses the explicitly selected `OpenSSL` backend; it never selects Vanetza's
  potentially-null `default` backend.
- Emits Root, AA and AT certificates using standard-profile OER encoding.
- Root and AA issue permissions explicitly cover AID 36 (CAM) and AID 37
  (DENM). Each AT explicitly carries both application permissions.
- Each issued certificate is ASN.1 validated and its primary ECC signature is
  verified before the generation is published.
- Private keys are written as unencrypted PKCS#8 PEM with mode `0600` in a
  generation directory with mode `0700`. This format is intended for the
  current C-02 resolver. Protect backups and the host accordingly.
- An issuance run is immutable. Existing runs are never overwritten. The tool
  stages a complete run and publishes it with a same-filesystem directory
  rename.
- The default is dry-run. No key or certificate files are created without
  `--execute`.

## Build

From the lab root:

```bash
./tools/build-standard-v3-issuer.sh
```

By default it uses `/usr/bin/g++-11` and
`$HOME/opt/vanetza-cpm-gcc11`. Override with `CXX` and `VANETZA_PREFIX` if
needed.

## Dry-run

```bash
./build/standard-v3-issuer/standard-v3-issuer \
  --lab-root "$HOME/final/v2x-pki-lab" \
  --vehicles 100 \
  --root-days 365 --aa-days 180 --ticket-days 30 \
  --dry-run
```

The above prints the plan and writes no files.

## Issue a controlled one-ticket chain

Only after the build and dry-run pass:

```bash
./build/standard-v3-issuer/standard-v3-issuer \
  --lab-root "$HOME/final/v2x-pki-lab" \
  --vehicles 1 \
  --root-days 365 --aa-days 180 --ticket-days 30 \
  --execute
```

The tool prints `GENERATION_PUBLISHED=...`. It creates a new immutable
subdirectory under:

```text
pki/domains/vehicle-v3/issuance/runs/
```

Each run has this shape:

```text
<run>/
├── authorities/
│   ├── root/root.pem, root.cert
│   └── aa/aa.pem, aa.cert
├── issued-tickets/dual-aid/
│   └── veh0-ticket-000.pem, veh0-ticket-000.cert
├── trust-store/trusted-root.cert
├── certificate-chain/{aa.cert,root.cert}
└── manifest.txt
```

For a fleet run, pass `--vehicles 100`; the ticket names are `veh0` through
`veh99`. Use `--start-index` and `--vehicle-prefix` where required by the SUMO
vehicle IDs.

## What this tool does not prove

The internal checks establish standard-profile OER validity, issuer-digest
binding, primary ECC signatures, AID policy fields and validity at issuance.
They do not, by themselves, prove acceptance by the C-02
`DefaultCertificateValidator`, that the consuming runtime has loaded the
published trust-store/issuer-chain paths, geofence policy,
revocation status, CAM/DENM message signing, or runtime delivery. Those remain
separate acceptance gates. No credentials should be copied into the historic
fixture directory.
