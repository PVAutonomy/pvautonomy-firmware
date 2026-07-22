#!/usr/bin/env python3
"""Fail-closed validator for the Onboarding Image release descriptor.

Validates ``onboarding/releases/0.1.0.json`` against the pinned WP2-B
release contract (Product Contract v1.4 / PD-13, ADR-0004 §§5, 7, 21) and —
optionally — verifies that a built four-file release bundle aligns with the
descriptor.

This alignment validation supplements, but does not replace, the canonical
WP2-A bundle validator that lives in the pinned source repository
(``tools/onboarding/validate_release_bundle.py`` in
``PVAutonomy/pvautonomy-config``).

Standard library only. Every violation is collected and reported; any
violation exits non-zero. The validator never repairs, never warns-and-passes.

With ``--github-output <path>`` the validator appends the *validated, fixed*
descriptor values as GitHub Actions step outputs — only after validation has
passed. Workflow logic must consume these validated outputs and never derive
trusted values from unvalidated JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# --- Pinned release contract (WP2-B for Onboarding 0.1.0) -------------------

VERSION = "0.1.0"
RELEASE_TAG = f"onboarding-v{VERSION}"
PROJECT_VERSION = f"onboarding-{VERSION}"

EXPECTED_DESCRIPTOR = {
    "schema_version": 1,
    "artifact_class": "onboarding_serial",
    "version": VERSION,
    "project_version": PROJECT_VERSION,
    "release_tag": RELEASE_TAG,
    "release_title": f"PVAutonomy Edge101 Onboarding Image {VERSION}",
    "publisher_repository": "PVAutonomy/pvautonomy-firmware",
    "source_repository": "PVAutonomy/pvautonomy-config",
    "source_commit": "bc761fc58fca1982df360c9df2dbf90a950e3e5a",
    "source_yaml": "esphome/edge101-factory-base.yaml",
    "esphome_version": "2025.12.0",
    "hardware_family": "edge101",
    "board": "esp32dev",
    "framework": "arduino",
    "artifact_name": f"edge101-onboarding-{VERSION}.factory.bin",
    "checksum_name": f"edge101-onboarding-{VERSION}.factory.bin.sha256",
    "manifest_name": f"edge101-onboarding-{VERSION}.manifest.json",
    "metadata_name": f"edge101-onboarding-{VERSION}.metadata.json",
}

RELEASE_BASE_URL = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/"
    f"{RELEASE_TAG}"
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S+)\n$")

# Production-OTA / secret material must never appear in the public
# Onboarding release chain (ADR-0004 §5 non-conflation, FEC-11).
_FORBIDDEN_SUBSTRINGS = (
    "firmware.ota.bin",
    "ota.md5",
    "ota.path",
    "/firmware/edge101/",
    "secrets.yaml",
    "password",
    "api_key",
    "credential",
    "noise_psk",
)

_FILENAME_KEYS = ("artifact_name", "checksum_name", "manifest_name", "metadata_name")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expect(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _load_json(path: Path, errors: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        errors.append(f"{path}: unreadable or invalid JSON ({err})")
        return None


def validate_descriptor(descriptor_path: Path) -> tuple[list[str], dict | None]:
    """Return (violations, descriptor). Descriptor is None when unreadable."""
    errors: list[str] = []
    descriptor = _load_json(descriptor_path, errors)
    if descriptor is None:
        return errors, None
    if not isinstance(descriptor, dict):
        return [f"{descriptor_path}: descriptor must be a JSON object"], None

    expected_keys = set(EXPECTED_DESCRIPTOR)
    actual_keys = set(descriptor)
    for missing in sorted(expected_keys - actual_keys):
        errors.append(f"descriptor: missing required key {missing!r}")
    for extra in sorted(actual_keys - expected_keys):
        errors.append(f"descriptor: unexpected extra key {extra!r}")

    for key, expected_value in EXPECTED_DESCRIPTOR.items():
        if key in descriptor and descriptor[key] != expected_value:
            errors.append(
                f"descriptor: {key} = {descriptor[key]!r}, "
                f"expected {expected_value!r}"
            )

    source_commit = descriptor.get("source_commit")
    _expect(
        errors,
        isinstance(source_commit, str)
        and _COMMIT_RE.match(source_commit) is not None,
        f"descriptor: source_commit must be 40-char lowercase hex, "
        f"got {source_commit!r}",
    )

    filenames = [descriptor.get(key) for key in _FILENAME_KEYS if key in descriptor]
    _expect(
        errors,
        len(filenames) == len(set(filenames)),
        "descriptor: artifact filenames must be unique",
    )

    serialized = json.dumps(descriptor).lower()
    for needle in _FORBIDDEN_SUBSTRINGS:
        _expect(
            errors,
            needle not in serialized,
            f"descriptor: forbidden Production/secret reference {needle!r}",
        )

    version = descriptor.get("version")
    _expect(
        errors,
        descriptor.get("release_tag") == f"onboarding-v{version}",
        "descriptor: release_tag does not agree with version",
    )
    _expect(
        errors,
        descriptor.get("project_version") == f"onboarding-{version}",
        "descriptor: project_version does not agree with version",
    )

    return errors, descriptor


def validate_bundle_alignment(descriptor: dict, bundle_dir: Path) -> list[str]:
    """Verify a built four-file bundle agrees with the validated descriptor."""
    errors: list[str] = []
    if not bundle_dir.is_dir():
        return [f"bundle directory not found: {bundle_dir}"]

    expected_files = sorted(descriptor[key] for key in _FILENAME_KEYS)
    present = sorted(p.name for p in bundle_dir.iterdir())
    for name in expected_files:
        _expect(errors, name in present, f"bundle: missing required file {name}")
    for name in present:
        _expect(errors, name in expected_files, f"bundle: unexpected extra file {name}")
    if errors:
        return errors

    binary = bundle_dir / descriptor["artifact_name"]
    size_bytes = binary.stat().st_size
    _expect(errors, size_bytes > 0, "bundle: binary is zero bytes")
    actual_sha = _sha256_file(binary)

    checksum_raw = (bundle_dir / descriptor["checksum_name"]).read_text(
        encoding="utf-8"
    )
    match = _CHECKSUM_LINE_RE.match(checksum_raw)
    if match is None:
        errors.append(
            "bundle: checksum file malformed — expected lowercase "
            "'<sha256>  <filename>' with trailing newline"
        )
    else:
        _expect(
            errors,
            match.group(1) == actual_sha,
            "bundle: checksum does not match the binary",
        )
        _expect(
            errors,
            match.group(2) == descriptor["artifact_name"],
            "bundle: checksum filename field disagrees with descriptor",
        )

    expected_artifact_url = f"{RELEASE_BASE_URL}/{descriptor['artifact_name']}"
    expected_manifest_url = f"{RELEASE_BASE_URL}/{descriptor['manifest_name']}"

    metadata = _load_json(bundle_dir / descriptor["metadata_name"], errors)
    if metadata is not None:
        for meta_key, desc_key in (
            ("version", "version"),
            ("project_version", "project_version"),
            ("release_tag", "release_tag"),
            ("artifact_name", "artifact_name"),
            ("manifest_name", "manifest_name"),
            ("source_repository", "source_repository"),
            ("source_commit", "source_commit"),
            ("esphome_version", "esphome_version"),
            ("hardware_family", "hardware_family"),
            ("board", "board"),
            ("framework", "framework"),
        ):
            _expect(
                errors,
                metadata.get(meta_key) == descriptor[desc_key],
                f"bundle metadata: {meta_key} = {metadata.get(meta_key)!r} "
                f"disagrees with descriptor {desc_key} = {descriptor[desc_key]!r}",
            )
        _expect(
            errors,
            metadata.get("artifact_class") == descriptor["artifact_class"],
            "bundle metadata: artifact_class disagrees with descriptor",
        )
        _expect(
            errors,
            metadata.get("sha256") == actual_sha,
            "bundle metadata: sha256 disagrees with the binary",
        )
        _expect(
            errors,
            metadata.get("size_bytes") == size_bytes,
            "bundle metadata: size_bytes disagrees with the binary",
        )
        _expect(
            errors,
            metadata.get("immutable_artifact_url") == expected_artifact_url,
            f"bundle metadata: immutable_artifact_url != {expected_artifact_url}",
        )
        _expect(
            errors,
            metadata.get("immutable_manifest_url") == expected_manifest_url,
            f"bundle metadata: immutable_manifest_url != {expected_manifest_url}",
        )

    manifest = _load_json(bundle_dir / descriptor["manifest_name"], errors)
    if manifest is not None:
        _expect(
            errors,
            manifest.get("version") == descriptor["version"],
            "bundle manifest: version disagrees with descriptor",
        )
        serialized = json.dumps(manifest).lower()
        for needle in ("firmware.ota.bin", '"ota"', "md5"):
            _expect(
                errors,
                needle not in serialized,
                f"bundle manifest: forbidden Production-OTA content {needle!r}",
            )
        builds = manifest.get("builds")
        if not isinstance(builds, list) or len(builds) != 1:
            errors.append("bundle manifest: exactly one build required")
        else:
            parts = builds[0].get("parts")
            if not isinstance(parts, list) or len(parts) != 1:
                errors.append("bundle manifest: exactly one part required")
            else:
                part = parts[0]
                _expect(
                    errors,
                    type(part.get("offset")) is int and part.get("offset") == 0,
                    "bundle manifest: part offset must be integer 0",
                )
                _expect(
                    errors,
                    part.get("path") == expected_artifact_url,
                    "bundle manifest: part path is not the immutable "
                    f"release URL {expected_artifact_url}",
                )

    return errors


def emit_github_outputs(descriptor: dict, output_path: Path) -> None:
    """Append validated descriptor values as GitHub Actions step outputs.

    Only called after validation has passed; values are the fixed, validated
    contract values — never unvalidated JSON.
    """
    lines = [f"{key}={descriptor[key]}" for key in EXPECTED_DESCRIPTOR]
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--descriptor",
        required=True,
        type=Path,
        help="path to the Onboarding release descriptor JSON",
    )
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=None,
        help="optional: built four-file bundle to verify against the descriptor",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=None,
        help="optional: append validated descriptor values as step outputs "
        "(e.g. $GITHUB_OUTPUT); only written when validation passes",
    )
    args = parser.parse_args(argv)

    errors, descriptor = validate_descriptor(args.descriptor)
    if descriptor is not None and not errors and args.bundle_dir is not None:
        errors.extend(validate_bundle_alignment(descriptor, args.bundle_dir))

    if errors:
        print("ONBOARDING RELEASE VALIDATION FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    if args.github_output is not None:
        emit_github_outputs(descriptor, args.github_output)

    scope = "descriptor" if args.bundle_dir is None else "descriptor + bundle alignment"
    print(f"ONBOARDING RELEASE VALID ({scope}): {args.descriptor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
