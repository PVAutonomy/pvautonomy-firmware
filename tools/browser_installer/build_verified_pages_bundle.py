#!/usr/bin/env python3
"""Build the verified Cloudflare-Pages staging bundle for the browser installer.

ADR-0004 §6.1 (pvautonomy-config @ 7c73d6ca) — *verified same-origin serving*:

* The GitHub Release stays the canonical release/identity/manual source.
* Before every deployment this tool fetches the published manifest and image
  from exactly the pinned release URLs, verifies size + SHA-256 against the
  versioned trusted pins (`release-pins/*.json`), derives the same-origin
  serving manifest by ONE exact byte substitution, and stages everything into
  a fresh output directory OUTSIDE the repository.
* Any mismatch aborts fail-closed; nothing is moved to its final staging path
  before every verification has passed; nothing in the repository is written.
* No firmware binary ever enters the Git tree; there is no Git LFS.

The tool never deletes files, never "cleans" an existing output directory,
never uses credentials, and never selects a different release version.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CHUNK_SIZE = 64 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_PIN_KEYS = frozenset(
    {
        "schema_version",
        "artifact_class",
        "version",
        "release_tag",
        "release_page_url",
        "manifest_name",
        "manifest_url",
        "manifest_size",
        "manifest_sha256",
        "manifest_version_field",
        "image_name",
        "image_url",
        "image_size",
        "image_sha256",
        "serving_dir",
        "serving_manifest_path",
        "serving_image_path",
        "absolute_image_url_token",
        "relative_image_token",
        "substitution_count",
        "builds_count",
        "parts_count",
        "chip_family",
        "offset",
        "redirect_host_allowlist",
    }
)

RELEASE_DOWNLOAD_PREFIX = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/"
)
RELEASE_TAG_PREFIX = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/tag/"
)


class PinError(ValueError):
    """Trusted-pin configuration is invalid — fail closed."""


class BundleError(RuntimeError):
    """Bundle construction failed — fail closed, no final artifacts."""


# ---------------------------------------------------------------------------
# Trusted pins (strict, fail-closed)
# ---------------------------------------------------------------------------


def _require_sha256(value, field):
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise PinError(f"{field}: not a lowercase 64-hex SHA-256: {value!r}")
    return value


def _require_positive_int(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PinError(f"{field}: not a positive integer: {value!r}")
    return value


def _require_relative_path(value, field):
    if not isinstance(value, str) or not value:
        raise PinError(f"{field}: empty")
    if value.startswith(("/", "\\")) or ":" in value.split("/")[0]:
        raise PinError(f"{field}: absolute paths are forbidden: {value!r}")
    parts = value.split("/")
    if ".." in parts or "." in parts:
        raise PinError(f"{field}: traversal segment forbidden: {value!r}")
    if "latest" in value:
        raise PinError(f"{field}: '/latest/' style paths are forbidden: {value!r}")
    if "ota" in value.lower():
        raise PinError(f"{field}: OTA paths are forbidden: {value!r}")
    return value


def _require_https_release_url(value, field, expected_prefix, expected_suffix):
    if not isinstance(value, str) or not value.startswith(expected_prefix):
        raise PinError(f"{field}: must start with {expected_prefix}: {value!r}")
    if "/latest/" in value or value.endswith("/latest"):
        raise PinError(f"{field}: '/latest/' URLs are forbidden: {value!r}")
    if expected_suffix and not value.endswith(expected_suffix):
        raise PinError(f"{field}: must end with {expected_suffix}: {value!r}")
    return value


def load_pins(path: Path) -> dict:
    """Load and strictly validate the trusted-pin configuration."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PinError("pin configuration must be a JSON object")

    keys = set(raw)
    missing = REQUIRED_PIN_KEYS - keys
    unknown = keys - REQUIRED_PIN_KEYS
    if missing:
        raise PinError(f"missing required pin keys: {sorted(missing)}")
    if unknown:
        raise PinError(f"unknown pin keys: {sorted(unknown)}")

    if raw["schema_version"] != 1:
        raise PinError(f"unsupported schema_version: {raw['schema_version']!r}")
    if raw["artifact_class"] != "onboarding_serial":
        raise PinError(f"artifact_class must be onboarding_serial: {raw['artifact_class']!r}")

    version = raw["version"]
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version):
        raise PinError(f"version: not a semver string: {version!r}")
    if raw["release_tag"] != f"onboarding-v{version}":
        raise PinError(f"release_tag does not match version: {raw['release_tag']!r}")

    manifest_name = raw["manifest_name"]
    image_name = raw["image_name"]
    if manifest_name != f"edge101-onboarding-{version}.manifest.json":
        raise PinError(f"manifest_name does not match version: {manifest_name!r}")
    if image_name != f"edge101-onboarding-{version}.factory.bin":
        raise PinError(f"image_name does not match version: {image_name!r}")
    for name in (manifest_name, image_name):
        if "ota" in name.lower():
            raise PinError(f"OTA artifact names are forbidden: {name!r}")

    tag_prefix = RELEASE_DOWNLOAD_PREFIX + raw["release_tag"] + "/"
    _require_https_release_url(
        raw["release_page_url"], "release_page_url", RELEASE_TAG_PREFIX, raw["release_tag"]
    )
    _require_https_release_url(raw["manifest_url"], "manifest_url", tag_prefix, manifest_name)
    _require_https_release_url(raw["image_url"], "image_url", tag_prefix, image_name)

    _require_positive_int(raw["manifest_size"], "manifest_size")
    _require_positive_int(raw["image_size"], "image_size")
    _require_sha256(raw["manifest_sha256"], "manifest_sha256")
    _require_sha256(raw["image_sha256"], "image_sha256")
    if raw["manifest_version_field"] != version:
        raise PinError(
            f"manifest_version_field must equal version: {raw['manifest_version_field']!r}"
        )

    serving_dir = _require_relative_path(raw["serving_dir"], "serving_dir")
    serving_manifest = _require_relative_path(
        raw["serving_manifest_path"], "serving_manifest_path"
    )
    serving_image = _require_relative_path(raw["serving_image_path"], "serving_image_path")
    if serving_manifest != f"{serving_dir}/{manifest_name}":
        raise PinError(f"serving_manifest_path inconsistent: {serving_manifest!r}")
    if serving_image != f"{serving_dir}/{image_name}":
        raise PinError(f"serving_image_path inconsistent: {serving_image!r}")

    if raw["absolute_image_url_token"] != raw["image_url"]:
        raise PinError("absolute_image_url_token must equal image_url")
    if raw["relative_image_token"] != f"./{image_name}":
        raise PinError(f"relative_image_token must be ./{image_name}")

    for field, expected in (
        ("substitution_count", 1),
        ("builds_count", 1),
        ("parts_count", 1),
    ):
        if raw[field] != expected:
            raise PinError(f"{field} must be exactly {expected}: {raw[field]!r}")
    if raw["chip_family"] != "ESP32":
        raise PinError(f"chip_family must be ESP32: {raw['chip_family']!r}")
    if isinstance(raw["offset"], bool) or raw["offset"] != 0:
        raise PinError(f"offset must be integer 0: {raw['offset']!r}")

    allowlist = raw["redirect_host_allowlist"]
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or not all(isinstance(h, str) and h and "/" not in h for h in allowlist)
    ):
        raise PinError(f"redirect_host_allowlist invalid: {allowlist!r}")
    if "github.com" not in allowlist:
        raise PinError("redirect_host_allowlist must contain github.com")

    return raw


# ---------------------------------------------------------------------------
# Serving-manifest derivation (single exact byte substitution — no re-serialize)
# ---------------------------------------------------------------------------


def derive_serving_manifest(published: bytes, pins: dict) -> bytes:
    """Derive the same-origin serving manifest from verified published bytes.

    The ONLY permitted difference is one substitution of the pinned absolute
    image URL by the pinned relative token. Everything else is proven
    byte-identical via the round-trip check.
    """
    if len(published) != pins["manifest_size"]:
        raise BundleError(
            f"published manifest size {len(published)} != pinned {pins['manifest_size']}"
        )
    digest = hashlib.sha256(published).hexdigest()
    if digest != pins["manifest_sha256"]:
        raise BundleError(f"published manifest sha256 {digest} != pinned")

    old = pins["absolute_image_url_token"].encode("ascii")
    new = pins["relative_image_token"].encode("ascii")
    if published.count(old) != 1:
        raise BundleError(
            f"absolute image URL token must occur exactly once, found {published.count(old)}"
        )
    if published.count(new) != 0:
        raise BundleError("relative token pre-exists in published manifest")

    serving = published.replace(old, new, 1)

    # Round-trip proof: substituting back must reproduce the published bytes.
    if serving.count(new) != 1:
        raise BundleError("relative token must occur exactly once after substitution")
    round_trip = serving.replace(new, old, 1)
    if round_trip != published:
        raise BundleError("round-trip does not reproduce the published bytes")
    if hashlib.sha256(round_trip).hexdigest() != pins["manifest_sha256"]:
        raise BundleError("round-trip sha256 mismatch")

    # Structural invariants (validation-only parse; the parse result is never
    # re-serialized — the served bytes are `serving` exactly as derived).
    try:
        text = serving.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - ascii subset
        raise BundleError(f"serving manifest is not valid UTF-8: {exc}") from exc
    try:
        doc = json.loads(text)
        published_doc = json.loads(published.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise BundleError(f"serving manifest is not valid JSON: {exc}") from exc

    if doc.get("version") != pins["manifest_version_field"]:
        raise BundleError(f"manifest version field is {doc.get('version')!r}")
    if doc.get("manifest_version") != published_doc.get("manifest_version"):
        raise BundleError("manifest_version changed")
    if doc.get("new_install_prompt_erase") is not False:
        raise BundleError("new_install_prompt_erase must remain exactly false")

    builds = doc.get("builds")
    if not isinstance(builds, list) or len(builds) != pins["builds_count"]:
        raise BundleError(f"builds must be a list of exactly {pins['builds_count']}")
    build = builds[0]
    if set(build) != {"chipFamily", "parts"}:
        raise BundleError(f"unexpected build keys: {sorted(build)}")
    if build["chipFamily"] != pins["chip_family"]:
        raise BundleError(f"chipFamily must be {pins['chip_family']}")
    parts = build["parts"]
    if not isinstance(parts, list) or len(parts) != pins["parts_count"]:
        raise BundleError(f"parts must be a list of exactly {pins['parts_count']}")
    part = parts[0]
    if set(part) != {"path", "offset"}:
        raise BundleError(f"unexpected part keys: {sorted(part)}")
    if part["path"] != pins["relative_image_token"]:
        raise BundleError(f"part path must be the relative token: {part['path']!r}")
    if isinstance(part["offset"], bool) or part["offset"] != 0:
        raise BundleError(f"offset must be integer 0: {part['offset']!r}")
    if "ota" in text.lower():
        raise BundleError("OTA fields/paths are forbidden in the serving manifest")

    return serving


# ---------------------------------------------------------------------------
# Fetching (streamed, size- and hash-verified, HTTPS + redirect allowlist)
# ---------------------------------------------------------------------------


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowlist):
        self._allowlist = frozenset(allowlist)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https":
            raise BundleError(f"redirect to non-HTTPS URL refused: {newurl}")
        if parsed.hostname not in self._allowlist:
            raise BundleError(f"redirect host not in allowlist: {parsed.hostname!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrlFetcher:
    """Streamed HTTPS fetcher enforcing the pin's size and SHA-256 in flight."""

    def __init__(self, allowlist, timeout=60):
        self._allowlist = list(allowlist)
        self._timeout = timeout
        self._opener = urllib.request.build_opener(
            _AllowlistRedirectHandler(self._allowlist)
        )

    def fetch(self, url: str, expected_size: int, expected_sha256: str) -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise BundleError(f"non-HTTPS URL refused: {url}")
        if parsed.hostname not in self._allowlist:
            raise BundleError(f"URL host not in allowlist: {parsed.hostname!r}")
        request = urllib.request.Request(
            url, headers={"User-Agent": "pvautonomy-pages-bundle/1.0"}
        )
        hasher = hashlib.sha256()
        chunks = []
        received = 0
        with self._opener.open(request, timeout=self._timeout) as response:
            if response.status != 200:
                raise BundleError(f"HTTP {response.status} for {url}")
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                received += len(chunk)
                if received > expected_size:
                    raise BundleError(
                        f"download exceeds pinned size {expected_size}: {url}"
                    )
                hasher.update(chunk)
                chunks.append(chunk)
        if received != expected_size:
            raise BundleError(
                f"download size {received} != pinned {expected_size}: {url}"
            )
        digest = hasher.hexdigest()
        if digest != expected_sha256:
            raise BundleError(f"download sha256 {digest} != pinned: {url}")
        return b"".join(chunks)


def _verify_bytes(data: bytes, expected_size: int, expected_sha256: str, label: str):
    """Defense-in-depth re-verification independent of the fetcher."""
    if len(data) != expected_size:
        raise BundleError(f"{label}: size {len(data)} != pinned {expected_size}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise BundleError(f"{label}: sha256 {digest} != pinned")


# ---------------------------------------------------------------------------
# Bundle construction
# ---------------------------------------------------------------------------

STATIC_REQUIRED = ("index.html", "_headers", "assets", "vendor")


def build_bundle(repo_root: Path, pins: dict, output_dir: Path, fetcher) -> dict:
    """Assemble the verified Pages staging bundle in ``output_dir``.

    Nothing is moved to its final serving path before every verification has
    passed. On any error the final serving paths stay absent.
    """
    repo_root = Path(repo_root).resolve()
    installer_dir = repo_root / "installer"
    output_dir = Path(output_dir).resolve()

    if output_dir == repo_root or repo_root in output_dir.parents:
        raise BundleError(f"output directory must be outside the repository: {output_dir}")
    if output_dir.exists():
        if not output_dir.is_dir():
            raise BundleError(f"output path exists and is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise BundleError(f"output directory is not empty: {output_dir}")
    else:
        output_dir.mkdir(parents=True)

    for required in STATIC_REQUIRED:
        if not (installer_dir / required).exists():
            raise BundleError(f"missing static source: installer/{required}")

    # 1) Static installer content (page, headers, assets, full vendor tree).
    for entry in sorted(installer_dir.iterdir()):
        if entry.name.startswith("."):
            continue
        target = output_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)

    serving_manifest_final = output_dir / pins["serving_manifest_path"]
    serving_image_final = output_dir / pins["serving_image_path"]
    for final in (serving_manifest_final, serving_image_final):
        resolved = final.resolve()
        if output_dir not in resolved.parents:
            raise BundleError(f"serving path escapes the output directory: {final}")

    # 2) Fetch + verify the published release files; derive the serving
    #    manifest. Everything lands in a private tmp dir first.
    tmp_dir = Path(tempfile.mkdtemp(prefix=".staging-", dir=output_dir))

    published_manifest = fetcher.fetch(
        pins["manifest_url"], pins["manifest_size"], pins["manifest_sha256"]
    )
    _verify_bytes(
        published_manifest, pins["manifest_size"], pins["manifest_sha256"], "manifest"
    )
    serving_manifest = derive_serving_manifest(published_manifest, pins)

    image = fetcher.fetch(pins["image_url"], pins["image_size"], pins["image_sha256"])
    _verify_bytes(image, pins["image_size"], pins["image_sha256"], "image")

    tmp_manifest = tmp_dir / pins["manifest_name"]
    tmp_image = tmp_dir / pins["image_name"]
    tmp_manifest.write_bytes(serving_manifest)
    tmp_image.write_bytes(image)
    _verify_bytes(tmp_image.read_bytes(), pins["image_size"], pins["image_sha256"], "staged image")

    # 3) Only after ALL verifications: move to the final serving paths.
    serving_manifest_final.parent.mkdir(parents=True, exist_ok=True)
    tmp_manifest.replace(serving_manifest_final)
    tmp_image.replace(serving_image_final)
    tmp_dir.rmdir()

    return {
        "output_dir": str(output_dir),
        "serving_manifest": str(serving_manifest_final),
        "serving_image": str(serving_image_final),
        "image_sha256": pins["image_sha256"],
        "manifest_sha256_published": pins["manifest_sha256"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)

    pins = load_pins(args.pins)
    fetcher = UrlFetcher(pins["redirect_host_allowlist"])
    result = build_bundle(args.repo_root, pins, args.output, fetcher)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
