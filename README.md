# PVAutonomy Firmware Artifacts

Prebuilt firmware release distribution for PVAutonomy devices (OTA artifacts: `manifest.json` + `firmware.bin`).

## What’s inside

Firmware is published as **GitHub Releases**. Each release contains hardware-family folders with:

- `manifest.json` — metadata (version, channel, sha256, minimum requirements)
- `firmware.bin` — the firmware binary for OTA flashing

Recommended release asset names (download paths):
- `v1.0.3/edge101/manifest.json`
- `v1.0.3/edge101/firmware.bin`

## Download URL scheme (canonical)

Assets are fetched via:

- Manifest: `https://github.com/<OWNER>/<REPO>/releases/download/v{version}/{hw_family}/manifest.json`
- Firmware: `https://github.com/<OWNER>/<REPO>/releases/download/v{version}/{hw_family}/firmware.bin`

Example:
- `https://github.com/gshubi/pvautonomy-firmware/releases/download/v1.0.3/edge101/manifest.json`
- `https://github.com/gshubi/pvautonomy-firmware/releases/download/v1.0.3/edge101/firmware.bin`

## Manifest format (minimum fields)

`manifest.json` MUST include at least:

- `version` (e.g. `"1.0.3"`; no leading `v`)
- `channel` (e.g. `"stable"`, `"beta"`)
- `hw_family` (e.g. `"edge101"`)
- `sha256` (SHA-256 of `firmware.bin`, 64-char lowercase hex)
- `esphome_min` (e.g. `"2025.12.0"`)
- `build_date` (ISO 8601 date or datetime)

Optional but recommended:
- `changelog`
- `size_bytes`

## Integrity

Clients MUST verify the binary before flashing:
- compute `sha256(firmware.bin)` and compare with `manifest.json.sha256`
- if `size_bytes` is present, verify it matches the downloaded file size

## License

- **Repository content:** Apache-2.0 (see `LICENSE`)
- Note: `firmware.bin` may bundle third-party components; relevant notices should be documented in release notes or shipped as a `NOTICE` / `THIRD_PARTY_NOTICES` release asset if required.
