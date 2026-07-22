# PVAutonomy Firmware Artifacts

Public firmware artifact distribution for PVAutonomy Edge devices.

This repository publishes **two distinct artifact classes**. They are never
interchangeable (ADR-0004 §5 non-conflation):

| Artifact class | Release tags | What it is |
|---|---|---|
| **Onboarding Serial Image** | `onboarding-v*` | Public, secret-free, universal **full serial image** flashed at **offset 0** (browser/serial install). |
| Legacy Production/Factory OTA artifacts | `vfactory`, `v1.x` (and `gh-pages` firmware paths) | **Legacy artifact classes** from the pre-ADR-0004 OTA distribution model. Not the ADR-0004 Onboarding Image. |

## Onboarding Serial Image (`onboarding-v*`)

The Edge101 Onboarding Image (Product Contract v1.4 / PD-13, ADR-0004):

- is **public and secret-free** — it contains no device or customer secrets;
- is the **full serial image**, flashed at **offset 0** (ESP-Web-Tools
  `parts[]` contract);
- is available to **Managed and Open-Source users alike** — no payment,
  Build-Key, repository access, or GitHub account is required;
- is **NOT Production OTA firmware**: it must never be consumed by the
  Production OTA update path (`firmware.ota.bin` / OTA manifests are a
  strictly separate artifact class).

### Four-asset release contract

Every `onboarding-v<semver>` release carries exactly four assets:

1. `edge101-onboarding-<semver>.factory.bin` — the full serial image
2. `edge101-onboarding-<semver>.factory.bin.sha256` — lowercase SHA-256
   (`<hash>  <filename>` format)
3. `edge101-onboarding-<semver>.manifest.json` — ESP-Web-Tools serial-install
   manifest (one build, `chipFamily: ESP32`, one part at offset 0; never
   `ota`/`md5` fields)
4. `edge101-onboarding-<semver>.metadata.json` — release metadata (source
   commit, ESPHome version, hardware/board/framework, SHA-256, size,
   immutable URLs)

Clients MUST verify the binary against the published SHA-256 before flashing.

### Source authority

The canonical source of the Onboarding Image is
[`PVAutonomy/pvautonomy-config`](https://github.com/PVAutonomy/pvautonomy-config)
(`esphome/edge101-factory-base.yaml`) **at the exact commit pinned by the
release descriptor** under [`onboarding/releases/`](onboarding/releases/).
The source retains its historical internal "factory" filename/project name
for device-detection compatibility; released artifacts use the Onboarding
naming contract above.

### Publisher authority

This repository defines the **publisher gate**: each release is pinned by a
descriptor (`onboarding/releases/<semver>.json`) and validated by
[`scripts/validate_onboarding_release_descriptor.py`](scripts/validate_onboarding_release_descriptor.py).
Pull-request CI validates **only the public publisher contract** (tests +
descriptor); this public repository does **not** build from or check out the
private canonical source repository.

The release candidate itself is built at the exact descriptor-pinned source
commit **by the canonical source repository's own workflow**. Transferring
that candidate here and staging it as an exact draft release is the separate,
explicitly authorized **WP2-C ceremony**. The manual, confirmation-gated
[`onboarding-release.yml`](.github/workflows/onboarding-release.yml)
dispatch job only **validates and promotes an already staged draft** — it
never builds firmware and never creates a draft, release, tag, or asset.

**A draft, descriptor, or engineering artifact is not customer delivery.**
The **published** GitHub Release is the only customer-visible authority: an
Onboarding version exists for customers only once its `onboarding-v<semver>`
release is published there.

## Legacy artifacts (`vfactory`, `v1.x`, `gh-pages`)

The historical releases `vfactory`, `v1.0.3`, `v1.0.4` and the `gh-pages`
firmware paths are **legacy artifact classes** kept for existing devices and
historical reference. They are not the ADR-0004 Onboarding Image, are not
managed by the Onboarding publisher workflow, and are never modified by it.

## Status

**`onboarding-v0.1.0` is not published.** No browser installer and no
hardware validation are provided by this repository; the browser installer is
a separate work package (ADR-0004 §6). Publication of a given
`onboarding-v<semver>` release happens only through its own explicitly
authorized publication run (WP2-C: private-source build → candidate transfer
→ draft staging → manual promote).

## License

- **Repository content:** Apache-2.0 (see `LICENSE`)
- Note: firmware binaries may bundle third-party components; relevant
  notices should be documented in release notes or shipped as a `NOTICE` /
  `THIRD_PARTY_NOTICES` release asset if required.
