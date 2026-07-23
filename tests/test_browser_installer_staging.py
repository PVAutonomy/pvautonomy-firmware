"""Contract tests for the WP3-H1 verified Pages staging pipeline.

Covers (network-free, no browser, no device):

1. The trusted-pin configuration (strict, fail-closed loader).
2. The byte-exact serving-manifest derivation incl. the round-trip proof
   against the production golden bytes (439 B, SHA-256 ``139916b5…``).
3. The bundle tool core with an injected fetcher: success path, every
   fail-closed error path, and the no-partial-final-artifact guarantee.
4. A loopback HTTP smoke over a fully staged bundle built from synthetic
   image bytes (no real firmware is ever downloaded or checked in).

These tests never contact GitHub, Cloudflare, or any external host.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import http.server
import importlib.util
import json
import posixpath
import re
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "browser_installer" / "build_verified_pages_bundle.py"
PINS_PATH = (
    REPO_ROOT / "tools" / "browser_installer" / "release-pins" / "onboarding-0.1.0.json"
)
GOLDEN_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "browser_installer"
    / "edge101-onboarding-0.1.0.manifest.golden.json"
)

GOLDEN_SIZE = 439
GOLDEN_SHA256 = "139916b5e4d337879c0efa0197880f00c4d4e8bf8882de9b5ce1d963e0da3864"
IMAGE_SHA256 = "879afa1528c97548ed0ed82a859f408611a6c871fc3a97492f7d52dcb01cb9c1"
IMAGE_SIZE = 1156480
ABS_TOKEN = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/"
    "onboarding-v0.1.0/edge101-onboarding-0.1.0.factory.bin"
)
REL_TOKEN = "./edge101-onboarding-0.1.0.factory.bin"


def _load_tool():
    spec = importlib.util.spec_from_file_location("build_verified_pages_bundle", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_verified_pages_bundle"] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()

GOLDEN = GOLDEN_PATH.read_bytes()
CANONICAL_PINS = json.loads(PINS_PATH.read_text(encoding="utf-8"))


def _pins_with(tmp_path: Path, mutate) -> Path:
    payload = json.loads(json.dumps(CANONICAL_PINS))
    mutate(payload)
    path = tmp_path / "pins.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _synthetic_image(size: int = 4096) -> bytes:
    return (b"\xe9wp3h1-synthetic-image\x00" * ((size // 23) + 1))[:size]


class FakeFetcher:
    """Injected fetcher: returns preset bytes per URL (or raises)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[str] = []

    def fetch(self, url, expected_size, expected_sha256):
        self.calls.append(url)
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result


def _pins_for_synthetic_image(image: bytes) -> dict:
    pins = json.loads(json.dumps(CANONICAL_PINS))
    pins["image_size"] = len(image)
    pins["image_sha256"] = hashlib.sha256(image).hexdigest()
    return pins


def _fetcher_for(pins: dict, manifest: bytes, image: bytes) -> FakeFetcher:
    return FakeFetcher({pins["manifest_url"]: manifest, pins["image_url"]: image})


# ---------------------------------------------------------------------------
# 1. Trusted pins — strict, fail-closed
# ---------------------------------------------------------------------------


class TestTrustedPins:
    def test_canonical_pins_load(self):
        pins = tool.load_pins(PINS_PATH)
        assert pins["manifest_size"] == GOLDEN_SIZE
        assert pins["manifest_sha256"] == GOLDEN_SHA256
        assert pins["image_size"] == IMAGE_SIZE
        assert pins["image_sha256"] == IMAGE_SHA256
        assert pins["absolute_image_url_token"] == ABS_TOKEN
        assert pins["relative_image_token"] == REL_TOKEN
        assert pins["serving_manifest_path"] == (
            "firmware/onboarding-0.1.0/edge101-onboarding-0.1.0.manifest.json"
        )
        assert pins["serving_image_path"] == (
            "firmware/onboarding-0.1.0/edge101-onboarding-0.1.0.factory.bin"
        )
        assert pins["chip_family"] == "ESP32"
        assert pins["offset"] == 0

    def test_unknown_key_fails(self, tmp_path):
        with pytest.raises(tool.PinError, match="unknown"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(extra=1)))

    def test_missing_key_fails(self, tmp_path):
        with pytest.raises(tool.PinError, match="missing"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.pop("image_sha256")))

    @pytest.mark.parametrize("bad", ["", "abc", "G" * 64, "139916B5" + "0" * 56])
    def test_invalid_sha_fails(self, tmp_path, bad):
        with pytest.raises(tool.PinError, match="SHA-256"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(manifest_sha256=bad)))

    @pytest.mark.parametrize("bad", [0, -1, "439", True])
    def test_invalid_size_fails(self, tmp_path, bad):
        with pytest.raises(tool.PinError, match="positive integer"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(manifest_size=bad)))

    def test_latest_url_fails(self, tmp_path):
        bad = "https://github.com/PVAutonomy/pvautonomy-firmware/releases/latest"
        with pytest.raises(tool.PinError):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(manifest_url=bad)))

    def test_ota_identity_fails(self, tmp_path):
        def mutate(p):
            p["image_name"] = "firmware.ota.bin"

        with pytest.raises(tool.PinError):
            tool.load_pins(_pins_with(tmp_path, mutate))

    def test_absolute_serving_path_fails(self, tmp_path):
        with pytest.raises(tool.PinError, match="absolute"):
            tool.load_pins(
                _pins_with(tmp_path, lambda p: p.update(serving_dir="/firmware/x"))
            )

    def test_traversal_serving_path_fails(self, tmp_path):
        def mutate(p):
            p["serving_dir"] = "firmware/../secrets"
            p["serving_manifest_path"] = f"{p['serving_dir']}/{p['manifest_name']}"
            p["serving_image_path"] = f"{p['serving_dir']}/{p['image_name']}"

        with pytest.raises(tool.PinError, match="traversal"):
            tool.load_pins(_pins_with(tmp_path, mutate))

    def test_wrong_relative_token_fails(self, tmp_path):
        with pytest.raises(tool.PinError, match="relative_image_token"):
            tool.load_pins(
                _pins_with(tmp_path, lambda p: p.update(relative_image_token="./x.bin"))
            )

    def test_substitution_count_must_be_one(self, tmp_path):
        with pytest.raises(tool.PinError, match="substitution_count"):
            tool.load_pins(
                _pins_with(tmp_path, lambda p: p.update(substitution_count=2))
            )

    def test_wrong_chip_or_offset_fails(self, tmp_path):
        with pytest.raises(tool.PinError, match="ESP32"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(chip_family="ESP8266")))
        with pytest.raises(tool.PinError, match="offset"):
            tool.load_pins(_pins_with(tmp_path, lambda p: p.update(offset=4096)))


# ---------------------------------------------------------------------------
# 2. Serving-manifest derivation — production golden bytes + round trip
# ---------------------------------------------------------------------------


class TestManifestDerivation:
    def test_golden_fixture_matches_published_pins(self):
        assert len(GOLDEN) == GOLDEN_SIZE
        assert hashlib.sha256(GOLDEN).hexdigest() == GOLDEN_SHA256

    def test_derivation_single_substitution_and_round_trip(self):
        pins = tool.load_pins(PINS_PATH)
        serving = tool.derive_serving_manifest(GOLDEN, pins)
        assert serving != GOLDEN
        assert serving.count(REL_TOKEN.encode()) == 1
        assert serving.count(ABS_TOKEN.encode()) == 0
        # Round trip reproduces the published bytes bit-identically.
        round_trip = serving.replace(REL_TOKEN.encode(), ABS_TOKEN.encode(), 1)
        assert round_trip == GOLDEN
        assert hashlib.sha256(round_trip).hexdigest() == GOLDEN_SHA256
        # Exactly one contiguous byte region differs (the substituted token).
        doc = json.loads(serving.decode("utf-8"))
        assert doc["builds"][0]["parts"][0]["path"] == REL_TOKEN
        assert doc["builds"][0]["parts"][0]["offset"] == 0
        assert doc["builds"][0]["chipFamily"] == "ESP32"
        assert doc["version"] == "0.1.0"
        assert doc["new_install_prompt_erase"] is False

    def test_wrong_size_rejected(self):
        pins = tool.load_pins(PINS_PATH)
        with pytest.raises(tool.BundleError, match="size"):
            tool.derive_serving_manifest(GOLDEN + b"\n", pins)

    def test_wrong_sha_rejected(self):
        pins = tool.load_pins(PINS_PATH)
        tampered = GOLDEN.replace(b"0.1.0", b"0.9.9", 1)
        padded = tampered[:GOLDEN_SIZE].ljust(GOLDEN_SIZE, b" ")
        with pytest.raises(tool.BundleError, match="sha256"):
            tool.derive_serving_manifest(padded, pins)

    def _synthetic_manifest(self, mutate=None) -> tuple[bytes, dict]:
        doc = json.loads(GOLDEN.decode("utf-8"))
        if mutate:
            mutate(doc)
        data = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
        pins = json.loads(json.dumps(CANONICAL_PINS))
        pins["manifest_size"] = len(data)
        pins["manifest_sha256"] = hashlib.sha256(data).hexdigest()
        return data, pins

    def test_token_absent_rejected(self):
        data, pins = self._synthetic_manifest(
            lambda d: d["builds"][0]["parts"][0].update(path="https://example.com/x.bin")
        )
        with pytest.raises(tool.BundleError, match="exactly once"):
            tool.derive_serving_manifest(data, pins)

    def test_token_twice_rejected(self):
        def mutate(d):
            d["builds"][0]["parts"].append({"path": ABS_TOKEN, "offset": 0})

        data, pins = self._synthetic_manifest(mutate)
        with pytest.raises(tool.BundleError, match="exactly once"):
            tool.derive_serving_manifest(data, pins)

    def test_preexisting_relative_token_rejected(self):
        def mutate(d):
            d["name"] = f"x {REL_TOKEN}"

        data, pins = self._synthetic_manifest(mutate)
        with pytest.raises(tool.BundleError, match="pre-exists"):
            tool.derive_serving_manifest(data, pins)

    def test_second_build_rejected(self):
        def mutate(d):
            d["builds"].append({"chipFamily": "ESP32-S3", "parts": []})

        data, pins = self._synthetic_manifest(mutate)
        with pytest.raises(tool.BundleError, match="builds"):
            tool.derive_serving_manifest(data, pins)

    def test_second_part_rejected(self):
        def mutate(d):
            d["builds"][0]["parts"].append({"path": "./other.bin", "offset": 65536})

        data, pins = self._synthetic_manifest(mutate)
        with pytest.raises(tool.BundleError, match="parts"):
            tool.derive_serving_manifest(data, pins)

    def test_wrong_offset_rejected(self):
        data, pins = self._synthetic_manifest(
            lambda d: d["builds"][0]["parts"][0].update(offset=4096)
        )
        with pytest.raises(tool.BundleError, match="offset"):
            tool.derive_serving_manifest(data, pins)

    def test_wrong_chip_rejected(self):
        data, pins = self._synthetic_manifest(
            lambda d: d["builds"][0].update(chipFamily="ESP32-C3")
        )
        with pytest.raises(tool.BundleError, match="chipFamily"):
            tool.derive_serving_manifest(data, pins)

    def test_wrong_version_rejected(self):
        data, pins = self._synthetic_manifest(lambda d: d.update(version="0.2.0"))
        with pytest.raises(tool.BundleError, match="version"):
            tool.derive_serving_manifest(data, pins)

    def test_prompt_erase_true_rejected(self):
        data, pins = self._synthetic_manifest(
            lambda d: d.update(new_install_prompt_erase=True)
        )
        with pytest.raises(tool.BundleError, match="new_install_prompt_erase"):
            tool.derive_serving_manifest(data, pins)

    def test_ota_field_rejected(self):
        def mutate(d):
            d["builds"][0]["ota"] = {"md5": "d41d8cd9"}

        data, pins = self._synthetic_manifest(mutate)
        with pytest.raises(tool.BundleError, match="build keys"):
            tool.derive_serving_manifest(data, pins)

    def test_any_other_byte_change_detected(self):
        tampered = bytearray(GOLDEN)
        tampered[10] ^= 0x01
        pins = tool.load_pins(PINS_PATH)
        with pytest.raises(tool.BundleError, match="sha256"):
            tool.derive_serving_manifest(bytes(tampered), pins)


# ---------------------------------------------------------------------------
# 3. Bundle tool core — injected fetcher, fail-closed
# ---------------------------------------------------------------------------


class TestBuildBundle:
    def _build(self, tmp_path, image=None, manifest=GOLDEN, out=None):
        image = image if image is not None else _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        fetcher = _fetcher_for(pins, manifest, image)
        out = out or (tmp_path / "bundle")
        result = tool.build_bundle(REPO_ROOT, pins, out, fetcher)
        return out, pins, result

    def test_successful_bundle(self, tmp_path):
        out, pins, _ = self._build(tmp_path)
        assert (out / "index.html").read_bytes() == (
            REPO_ROOT / "installer" / "index.html"
        ).read_bytes()
        assert (out / "_headers").is_file()
        assert (out / "assets" / "installer.css").is_file()
        assert (out / "assets" / "serial-support.js").is_file()
        vendor_files = sorted(
            p.relative_to(out).as_posix() for p in (out / "vendor").rglob("*") if p.is_file()
        )
        repo_vendor = sorted(
            "vendor/" + p.relative_to(REPO_ROOT / "installer" / "vendor").as_posix()
            for p in (REPO_ROOT / "installer" / "vendor").rglob("*")
            if p.is_file()
        )
        assert vendor_files == repo_vendor
        serving_manifest = (out / pins["serving_manifest_path"]).read_bytes()
        assert serving_manifest.count(REL_TOKEN.encode()) == 1
        assert serving_manifest.replace(REL_TOKEN.encode(), ABS_TOKEN.encode(), 1) == GOLDEN
        image_bytes = (out / pins["serving_image_path"]).read_bytes()
        assert hashlib.sha256(image_bytes).hexdigest() == pins["image_sha256"]
        assert len(image_bytes) == pins["image_size"]

    def test_bundle_excludes_pins_tool_tests_git(self, tmp_path):
        out, _, _ = self._build(tmp_path)
        names = {p.name for p in out.rglob("*")}
        for forbidden in (
            "onboarding-0.1.0.json",  # pin config file name
            "build_verified_pages_bundle.py",
            "test_browser_installer_staging.py",
            ".git",
            "edge101-onboarding-0.1.0.factory.bin.sha256",
            "edge101-onboarding-0.1.0.metadata.json",
        ):
            assert forbidden not in names, f"bundle must not contain {forbidden}"
        assert not [p for p in out.rglob(".staging-*")], "tmp staging dir must be gone"

    def test_wrong_image_hash_fails_without_partial_finals(self, tmp_path):
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        wrong = image[:-1] + b"\x00"
        fetcher = _fetcher_for(pins, GOLDEN, wrong)
        out = tmp_path / "bundle"
        with pytest.raises(tool.BundleError, match="sha256"):
            tool.build_bundle(REPO_ROOT, pins, out, fetcher)
        assert not (out / pins["serving_image_path"]).exists()
        assert not (out / pins["serving_manifest_path"]).exists()

    def test_truncated_download_fails(self, tmp_path):
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        fetcher = _fetcher_for(pins, GOLDEN, image[:-10])
        with pytest.raises(tool.BundleError, match="size"):
            tool.build_bundle(REPO_ROOT, pins, tmp_path / "b", fetcher)

    def test_extra_bytes_fail(self, tmp_path):
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        fetcher = _fetcher_for(pins, GOLDEN, image + b"x")
        with pytest.raises(tool.BundleError, match="size"):
            tool.build_bundle(REPO_ROOT, pins, tmp_path / "b", fetcher)

    def test_http_error_propagates_without_partial_finals(self, tmp_path):
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        fetcher = FakeFetcher(
            {
                pins["manifest_url"]: GOLDEN,
                pins["image_url"]: urllib.error.URLError("boom"),
            }
        )
        out = tmp_path / "bundle"
        with pytest.raises(urllib.error.URLError):
            tool.build_bundle(REPO_ROOT, pins, out, fetcher)
        assert not (out / pins["serving_image_path"]).exists()
        assert not (out / pins["serving_manifest_path"]).exists()

    def test_nonempty_output_refused(self, tmp_path):
        out = tmp_path / "bundle"
        out.mkdir()
        (out / "leftover.txt").write_text("x")
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        with pytest.raises(tool.BundleError, match="not empty"):
            tool.build_bundle(REPO_ROOT, pins, out, _fetcher_for(pins, GOLDEN, image))
        assert (out / "leftover.txt").exists()  # nothing deleted

    def test_output_inside_repo_refused(self, tmp_path):
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        with pytest.raises(tool.BundleError, match="outside the repository"):
            tool.build_bundle(
                REPO_ROOT, pins, REPO_ROOT / "never-created", _fetcher_for(pins, GOLDEN, image)
            )
        assert not (REPO_ROOT / "never-created").exists()

    def test_missing_static_source_fails(self, tmp_path):
        fake_repo = tmp_path / "fake-repo"
        (fake_repo / "installer").mkdir(parents=True)
        image = _synthetic_image()
        pins = _pins_for_synthetic_image(image)
        with pytest.raises(tool.BundleError, match="missing static source"):
            tool.build_bundle(
                fake_repo, pins, tmp_path / "out", _fetcher_for(pins, GOLDEN, image)
            )

    def test_url_fetcher_refuses_disallowed_hosts(self):
        fetcher = tool.UrlFetcher(["github.com"])
        with pytest.raises(tool.BundleError, match="allowlist"):
            fetcher.fetch("https://evil.example.com/x", 1, "0" * 64)
        with pytest.raises(tool.BundleError, match="non-HTTPS"):
            fetcher.fetch("http://github.com/x", 1, "0" * 64)

    def test_redirect_handler_refuses_wrong_host(self):
        handler = tool._AllowlistRedirectHandler(["github.com"])
        req = urllib.request.Request("https://github.com/a")
        with pytest.raises(tool.BundleError, match="allowlist"):
            handler.redirect_request(
                req, None, 302, "Found", {}, "https://attacker.example/x"
            )
        with pytest.raises(tool.BundleError, match="non-HTTPS"):
            handler.redirect_request(
                req, None, 302, "Found", {}, "http://github.com/x"
            )


# ---------------------------------------------------------------------------
# 4. Loopback smoke over a fully staged bundle (synthetic image bytes)
# ---------------------------------------------------------------------------


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@contextlib.contextmanager
def _serve(root: Path):
    handler = functools.partial(_QuietHandler, directory=str(root))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def _reachable_modules(web_dir: Path) -> set[str]:
    imp = re.compile(r"""(?:\bfrom|\bimport)\s*(?:\(\s*)?["'`]([^"'`]+)["'`]""")
    seen: set[str] = set()
    stack = ["install-button.js"]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for target in imp.findall((web_dir / cur).read_text(encoding="utf-8")):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(cur), target))
            if (web_dir / resolved).is_file():
                stack.append(resolved)
    return seen


def test_staged_bundle_loopback_smoke(tmp_path):
    image = _synthetic_image(8192)
    pins = _pins_for_synthetic_image(image)
    out = tmp_path / "bundle"
    tool.build_bundle(REPO_ROOT, pins, out, _fetcher_for(pins, GOLDEN, image))

    js_types = {"text/javascript", "application/javascript"}
    with _serve(out) as base:
        def fetch(path):
            with urllib.request.urlopen(base + path, timeout=10) as resp:
                assert resp.status == 200, f"{path}: HTTP {resp.status}"
                return resp.headers.get_content_type(), resp.read()

        ctype, body = fetch("/")
        assert ctype == "text/html" and body == (out / "index.html").read_bytes()
        ctype, body = fetch("/index.html")
        assert ctype == "text/html" and body == (out / "index.html").read_bytes()
        ctype, body = fetch("/assets/installer.css")
        assert ctype == "text/css" and body == (out / "assets/installer.css").read_bytes()
        ctype, body = fetch("/assets/serial-support.js")
        assert ctype in js_types

        web = out / "vendor/esp-web-tools/10.4.0/web"
        modules = _reachable_modules(web)
        assert len(modules) >= 26
        for name in sorted(modules):
            ctype, body = fetch(f"/vendor/esp-web-tools/10.4.0/web/{name}")
            assert ctype in js_types, f"{name}: {ctype}"
            assert body == (web / name).read_bytes()

        ctype, body = fetch("/" + pins["serving_manifest_path"])
        assert ctype == "application/json"
        assert body == (out / pins["serving_manifest_path"]).read_bytes()
        assert body.count(REL_TOKEN.encode()) == 1

        _, body = fetch("/" + pins["serving_image_path"])
        assert body == image
