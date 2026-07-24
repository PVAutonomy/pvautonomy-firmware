"""Network-free contract tests for the WP3-M1 browser-installer monitor.

Everything runs with synthetic fetchers/responses — no Internet, Cloudflare,
GitHub, or DNS. Covers: strict config + activation, release-identity
verification, host/content verification, security- and cache-header
verification, the GitHub-Actions workflow contract, and the CLI behavior.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import urllib.parse
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = REPO_ROOT / "tools" / "browser_installer"
MONITOR_PATH = TOOL_DIR / "monitor_browser_installer.py"
TARGETS_PATH = TOOL_DIR / "monitor-targets.json"
PINS_PATH = TOOL_DIR / "release-pins" / "onboarding-0.1.0.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "browser-installer-monitor.yml"
GOLDEN = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "browser_installer"
    / "edge101-onboarding-0.1.0.manifest.golden.json"
).read_bytes()

INSTALLER = REPO_ROOT / "installer"
WEB = INSTALLER / "vendor/esp-web-tools/10.4.0/web"

PAGES_BASE = "https://pvautonomy-installer.pages.dev"
STABLE_BASE = "https://install.pvautonomy.com"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


mon = _load("monitor_browser_installer", MONITOR_PATH)
bundle = sys.modules["build_verified_pages_bundle"]

CANONICAL_TARGETS = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
CANONICAL_PINS = json.loads(PINS_PATH.read_text(encoding="utf-8"))

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; manifest-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "object-src 'none'; upgrade-insecure-requests"
)
PP = "serial=(self), usb=(), geolocation=(), camera=(), microphone=(), payment=(), fullscreen=(self)"
SEC_HEADERS = {
    "content-security-policy": CSP,
    "permissions-policy": PP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=15552000",
}
CACHE = {"cache-control": "public, max-age=31536000, immutable"}


# ---------------------------------------------------------------------------
# Synthetic environment
# ---------------------------------------------------------------------------


def _synthetic_image(size=4096) -> bytes:
    return (b"\xe9m1-synthetic\x00" * ((size // 14) + 1))[:size]


def _pins_file(tmp_path, image: bytes) -> Path:
    pins = json.loads(json.dumps(CANONICAL_PINS))
    pins["image_size"] = len(image)
    pins["image_sha256"] = hashlib.sha256(image).hexdigest()
    path = tmp_path / "pins.json"
    path.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
    return path


class FakeReleaseFetcher:
    """Mimics bundle.UrlFetcher: verifies size+sha in flight, fail-closed."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def fetch(self, url, expected_size, expected_sha256):
        self.calls.append(url)
        data = self.responses[url]
        if isinstance(data, Exception):
            raise data
        if len(data) > expected_size:
            raise bundle.BundleError(f"download exceeds pinned size {expected_size}: {url}")
        if len(data) != expected_size:
            raise bundle.BundleError(f"download size {len(data)} != pinned {expected_size}: {url}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_sha256:
            raise bundle.BundleError(f"download sha256 {digest} != pinned: {url}")
        return data


class FakeHostFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.requested = []

    def get(self, base_url, path):
        self.requested.append((base_url, path))
        result = self.responses[(base_url, path)]
        if isinstance(result, Exception):
            raise result
        headers, body = result
        return dict(headers), body


def _host_map(base, serving: bytes, image: bytes) -> dict:
    m = {}
    m[(base, "/")] = ({"content-type": "text/html; charset=utf-8", **SEC_HEADERS},
                      (INSTALLER / "index.html").read_bytes())
    m[(base, "/assets/installer.css")] = (
        {"content-type": "text/css"}, (INSTALLER / "assets/installer.css").read_bytes())
    m[(base, "/assets/serial-support.js")] = (
        {"content-type": "application/javascript"},
        (INSTALLER / "assets/serial-support.js").read_bytes())
    for js in WEB.glob("*.js"):
        headers = {"content-type": "application/javascript"}
        if js.name == "install-button.js":
            headers.update(CACHE)
        m[(base, f"/vendor/esp-web-tools/10.4.0/web/{js.name}")] = (headers, js.read_bytes())
    m[(base, mon.SERVING_MANIFEST_PATH)] = (
        {"content-type": "application/json", **CACHE}, serving)
    m[(base, mon.SERVING_IMAGE_PATH)] = (
        {"content-type": "application/octet-stream", **CACHE}, image)
    return m


@pytest.fixture()
def env(tmp_path):
    image = _synthetic_image()
    pins_path = _pins_file(tmp_path, image)
    pins = bundle.load_pins(pins_path)
    serving = bundle.derive_serving_manifest(GOLDEN, pins)
    release = FakeReleaseFetcher(
        {pins["manifest_url"]: GOLDEN, pins["image_url"]: image}
    )
    host = FakeHostFetcher({**_host_map(PAGES_BASE, serving, image),
                            **_host_map(STABLE_BASE, serving, image)})
    return {
        "image": image,
        "pins_path": pins_path,
        "pins": pins,
        "serving": serving,
        "release": release,
        "host": host,
    }


def _run(env, state="disabled", **overrides):
    return mon.run_monitor(
        state,
        targets_path=overrides.get("targets_path", TARGETS_PATH),
        pins_path=env["pins_path"],
        release_fetcher=overrides.get("release", env["release"]),
        host_fetcher=overrides.get("host", env["host"]),
    )


# ---------------------------------------------------------------------------
# 1. Config + activation
# ---------------------------------------------------------------------------


class TestConfigAndActivation:
    def test_canonical_targets_load(self):
        targets = mon.load_targets(TARGETS_PATH)
        assert [t["name"] for t in targets] == ["pages-production", "stable-install"]
        assert targets[0]["base_url"] == PAGES_BASE
        assert targets[1]["base_url"] == STABLE_BASE
        assert targets[0]["always_active"] is True
        assert targets[1]["always_active"] is False

    def _targets_with(self, tmp_path, mutate):
        payload = json.loads(json.dumps(CANONICAL_TARGETS))
        mutate(payload)
        p = tmp_path / "targets.json"
        p.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return p

    def test_unknown_top_key_rejected(self, tmp_path):
        p = self._targets_with(tmp_path, lambda d: d.update(extra=1))
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    def test_missing_target_rejected(self, tmp_path):
        p = self._targets_with(tmp_path, lambda d: d["targets"].pop())
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    @pytest.mark.parametrize(
        "bad",
        [
            "http://pvautonomy-installer.pages.dev",
            "https://pvautonomy-installer.pages.dev:8443",
            "https://user@pvautonomy-installer.pages.dev",
            "https://pvautonomy-installer.pages.dev/?x=1",
            "https://evil.example.com",
        ],
    )
    def test_bad_base_url_rejected(self, tmp_path, bad):
        p = self._targets_with(tmp_path, lambda d: d["targets"][0].update(base_url=bad))
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    @pytest.mark.parametrize("state", [None, ""])
    def test_missing_or_empty_state_rejected(self, state):
        targets = mon.load_targets(TARGETS_PATH)
        with pytest.raises(mon.MonitorError) as e:
            mon.resolve_activation(state, targets)
        assert e.value.category == "ACTIVATION"

    @pytest.mark.parametrize("state", ["Disabled", "ENABLED", "true", "1", "yes", "on"])
    def test_unknown_state_rejected(self, state):
        targets = mon.load_targets(TARGETS_PATH)
        with pytest.raises(mon.MonitorError) as e:
            mon.resolve_activation(state, targets)
        assert e.value.category == "ACTIVATION"

    def test_disabled_activates_only_pages(self):
        targets = mon.load_targets(TARGETS_PATH)
        active, inactive = mon.resolve_activation("disabled", targets)
        assert [t["name"] for t in active] == ["pages-production"]
        assert [t["name"] for t in inactive] == ["stable-install"]

    def test_enabled_activates_both(self):
        targets = mon.load_targets(TARGETS_PATH)
        active, inactive = mon.resolve_activation("enabled", targets)
        assert [t["name"] for t in active] == ["pages-production", "stable-install"]
        assert inactive == []

    def test_disabled_run_never_contacts_stable_host(self, env):
        report = _run(env, state="disabled")
        assert report["status"] == "ok"
        assert all(base == PAGES_BASE for base, _ in env["host"].requested)
        assert not any(base == STABLE_BASE for base, _ in env["host"].requested)
        assert report["active_hosts"] == ["pages-production"]
        assert report["inactive_hosts"] == ["stable-install"]

    def test_enabled_run_contacts_both_hosts(self, env):
        report = _run(env, state="enabled")
        bases = {base for base, _ in env["host"].requested}
        assert bases == {PAGES_BASE, STABLE_BASE}
        assert report["active_hosts"] == ["pages-production", "stable-install"]
        assert report["inactive_hosts"] == []


# ---------------------------------------------------------------------------
# 2. Release identity
# ---------------------------------------------------------------------------


class TestReleaseIdentity:
    def test_exact_release_accepted_and_serving_derived(self, env):
        report = _run(env)
        assert report["release_manifest"]["size"] == 439
        assert report["release_manifest"]["sha256"].startswith("139916b5")
        assert report["serving_manifest"]["size"] == len(env["serving"])
        assert report["serving_manifest"]["sha256"] == hashlib.sha256(env["serving"]).hexdigest()

    def test_manifest_tamper_rejected(self, env):
        pins = env["pins"]
        env["release"].responses[pins["manifest_url"]] = GOLDEN[:-1] + b" "
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "RELEASE_IDENTITY"
        assert env["host"].requested == []  # hosts never contacted after release failure

    def test_image_tamper_rejected(self, env):
        pins = env["pins"]
        env["release"].responses[pins["image_url"]] = env["image"][:-1] + b"\x00"
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "RELEASE_IDENTITY"
        assert env["host"].requested == []

    def test_oversize_stream_rejected(self, env):
        pins = env["pins"]
        env["release"].responses[pins["image_url"]] = env["image"] + b"x"
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "RELEASE_IDENTITY"

    def test_disallowed_redirect_rejected(self, env):
        pins = env["pins"]
        env["release"].responses[pins["manifest_url"]] = bundle.BundleError(
            "redirect host not in allowlist: 'evil.example.com'"
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "REDIRECT"
        assert "allowlist" in str(e.value)
        assert env["host"].requested == []


class TestReleaseErrorBoundary:
    """R1: every expectable release-fetch failure becomes a MonitorError."""

    def _raise_and_expect(self, env, exc, category):
        pins = env["pins"]
        env["release"].responses[pins["manifest_url"]] = exc
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        # Structured, not a raw urllib/http exception:
        assert isinstance(e.value, mon.MonitorError)
        assert e.value.category == category
        assert e.value.host == "github.com"
        assert "edge101-onboarding" in e.value.path
        # No host is ever contacted after a release failure:
        assert env["host"].requested == []
        return e.value

    def test_urlerror_becomes_dns_or_tls(self, env):
        import urllib.error
        err = self._raise_and_expect(
            env, urllib.error.URLError("synthetic TLS failure"), "DNS_OR_TLS"
        )
        assert "synthetic TLS failure" in str(err)

    def test_timeout_becomes_dns_or_tls(self, env):
        self._raise_and_expect(env, TimeoutError("synthetic timeout"), "DNS_OR_TLS")

    def test_connection_error_becomes_dns_or_tls(self, env):
        self._raise_and_expect(env, ConnectionResetError("peer reset"), "DNS_OR_TLS")

    def test_http_exception_becomes_dns_or_tls(self, env):
        import http.client
        self._raise_and_expect(
            env, http.client.RemoteDisconnected("closed"), "DNS_OR_TLS"
        )

    def test_httperror_becomes_http_status(self, env):
        import urllib.error
        pins = env["pins"]
        exc = urllib.error.HTTPError(
            pins["manifest_url"], 503, "Service Unavailable", None, None
        )
        err = self._raise_and_expect(env, exc, "HTTP_STATUS")
        assert "503" in str(err)

    def test_image_fetch_error_also_structured(self, env):
        import urllib.error
        pins = env["pins"]
        env["release"].responses[pins["image_url"]] = urllib.error.URLError("boom")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "DNS_OR_TLS"
        assert env["host"].requested == []

    def test_cli_reports_structured_error_without_traceback(self, env, capsys, monkeypatch):
        # The CLI boundary catches MonitorError only; the conversion above
        # guarantees operational errors arrive as MonitorError. Simulate the
        # full CLI path by monkeypatching run_monitor.
        import urllib.error

        def fake_run(*a, **k):
            raise mon.MonitorError("DNS_OR_TLS", "synthetic TLS failure", "github.com", "/x")

        monkeypatch.setenv(mon.ACTIVATION_ENV_VAR, "disabled")
        monkeypatch.setattr(mon, "run_monitor", fake_run)
        rc = mon.main([])
        captured = capsys.readouterr()
        assert rc == 1
        err = json.loads(captured.err)
        assert err["category"] == "DNS_OR_TLS"
        assert "Traceback" not in captured.err
        assert captured.out == ""


class TestConfigHardening:
    """R1: pin/config boundary must be structured — never a raw traceback."""

    def test_missing_pins_file_is_config_error(self, env, tmp_path):
        with pytest.raises(mon.MonitorError) as e:
            mon.run_monitor(
                "disabled",
                targets_path=TARGETS_PATH,
                pins_path=tmp_path / "does-not-exist.json",
                release_fetcher=env["release"],
                host_fetcher=env["host"],
            )
        assert e.value.category == "CONFIG"

    def test_invalid_pins_json_is_config_error(self, env, tmp_path):
        bad = tmp_path / "bad-pins.json"
        bad.write_text("{{{ not json", encoding="utf-8")
        with pytest.raises(mon.MonitorError) as e:
            mon.run_monitor(
                "disabled",
                targets_path=TARGETS_PATH,
                pins_path=bad,
                release_fetcher=env["release"],
                host_fetcher=env["host"],
            )
        assert e.value.category == "CONFIG"

    def test_targets_top_level_list_is_config_error(self, tmp_path):
        p = tmp_path / "targets.json"
        p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    def test_targets_not_a_list_is_config_error(self, tmp_path):
        payload = json.loads(json.dumps(CANONICAL_TARGETS))
        payload["targets"] = "not-a-list"
        p = tmp_path / "targets.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    def test_target_entry_not_object_is_config_error(self, tmp_path):
        payload = json.loads(json.dumps(CANONICAL_TARGETS))
        payload["targets"][0] = "just-a-string"
        p = tmp_path / "targets.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"

    def test_non_string_base_url_is_config_error(self, tmp_path):
        payload = json.loads(json.dumps(CANONICAL_TARGETS))
        payload["targets"][0]["base_url"] = 12345
        p = tmp_path / "targets.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(mon.MonitorError) as e:
            mon.load_targets(p)
        assert e.value.category == "CONFIG"


# ---------------------------------------------------------------------------
# 3. Host verification
# ---------------------------------------------------------------------------


class TestHostVerification:
    def test_all_paths_checked(self, env):
        report = _run(env)
        host = report["hosts"][0]
        # / + 2 assets + 26 vendor modules + manifest + image = 31
        assert host["paths_checked"] == 31
        assert host["tls"] == "verified"

    def test_http_status_error(self, env):
        env["host"].responses[(PAGES_BASE, "/assets/installer.css")] = mon.MonitorError(
            "HTTP_STATUS", "HTTP 404", "pages", "/assets/installer.css"
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "HTTP_STATUS"

    def test_redirect_rejected(self, env):
        env["host"].responses[(PAGES_BASE, "/")] = mon.MonitorError(
            "REDIRECT", "redirect 301 -> https://elsewhere", "pages", "/"
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "REDIRECT"

    def test_dns_or_tls_error(self, env):
        env["host"].responses[(PAGES_BASE, "/")] = mon.MonitorError(
            "DNS_OR_TLS", "certificate verify failed", "pages", "/"
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "DNS_OR_TLS"

    def test_wrong_mime_rejected(self, env):
        headers, body = env["host"].responses[(PAGES_BASE, "/assets/installer.css")]
        env["host"].responses[(PAGES_BASE, "/assets/installer.css")] = (
            {**headers, "content-type": "text/plain"}, body)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "MIME"

    def test_wrong_size_rejected(self, env):
        headers, body = env["host"].responses[(PAGES_BASE, "/assets/serial-support.js")]
        env["host"].responses[(PAGES_BASE, "/assets/serial-support.js")] = (headers, body + b"\n")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SIZE"

    def test_tampered_bytes_rejected(self, env):
        headers, body = env["host"].responses[(PAGES_BASE, "/")]
        tampered = body.replace(b"0.1.0", b"9.9.9", 1)
        tampered = tampered + b" " * (len(body) - len(tampered))
        env["host"].responses[(PAGES_BASE, "/")] = (headers, tampered[: len(body)])
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SHA256"

    def test_missing_vendor_chunk_rejected(self, env):
        victim = next(
            (PAGES_BASE, p) for (b, p) in env["host"].responses
            if b == PAGES_BASE and "stub_flasher_32-" in p
        )
        env["host"].responses[victim] = mon.MonitorError(
            "HTTP_STATUS", "HTTP 404", "pages", victim[1]
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "HTTP_STATUS"

    def test_tampered_vendor_chunk_rejected(self, env):
        victim = (PAGES_BASE, "/vendor/esp-web-tools/10.4.0/web/install-button.js")
        headers, body = env["host"].responses[victim]
        env["host"].responses[victim] = (headers, body[:-1] + b";")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SHA256"

    def test_serving_manifest_with_absolute_url_rejected(self, env):
        victim = (PAGES_BASE, mon.SERVING_MANIFEST_PATH)
        headers, _ = env["host"].responses[victim]
        env["host"].responses[victim] = (headers, GOLDEN)  # published bytes, not derived
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category in ("SIZE", "SHA256")

    def test_wrong_image_on_host_rejected(self, env):
        victim = (PAGES_BASE, mon.SERVING_IMAGE_PATH)
        headers, body = env["host"].responses[victim]
        env["host"].responses[victim] = (headers, body[:-1] + b"\xff")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SHA256"


# ---------------------------------------------------------------------------
# 4. Security / cache headers
# ---------------------------------------------------------------------------


class TestHeaders:
    def _root(self, env):
        return env["host"].responses[(PAGES_BASE, "/")]

    def _set_root_header(self, env, name, value):
        headers, body = self._root(env)
        headers = dict(headers)
        if value is None:
            headers.pop(name, None)
        else:
            headers[name] = value
        env["host"].responses[(PAGES_BASE, "/")] = (headers, body)

    def test_good_headers_accepted(self, env):
        report = _run(env)
        assert report["hosts"][0]["security_headers"] == "ok"
        assert report["hosts"][0]["cache_headers"] == "ok"

    @pytest.mark.parametrize(
        "name", ["content-security-policy", "permissions-policy",
                  "x-content-type-options", "strict-transport-security"]
    )
    def test_missing_header_rejected(self, env, name):
        self._set_root_header(env, name, None)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_missing_csp_directive_rejected(self, env):
        weakened = CSP.replace("frame-ancestors 'none'; ", "")
        self._set_root_header(env, "content-security-policy", weakened)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    @pytest.mark.parametrize("bad", ["script-src 'self' 'unsafe-inline'",
                                     "script-src 'self' 'unsafe-eval'"])
    def test_unsafe_csp_rejected(self, env, bad):
        self._set_root_header(env, "content-security-policy", CSP.replace("script-src 'self'", bad))
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_serial_disabled_rejected(self, env):
        self._set_root_header(env, "permissions-policy", PP.replace("serial=(self)", "serial=()"))
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_hsts_extension_rejected(self, env):
        self._set_root_header(env, "strict-transport-security",
                              "max-age=15552000; includeSubDomains")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_header_whitespace_and_order_normalized(self, env):
        shuffled = (
            "upgrade-insecure-requests; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'none'; base-uri 'none'; manifest-src 'self'; "
            "connect-src   'self'; img-src 'self'   data:; style-src 'self'; "
            "script-src 'self'; default-src 'none'"
        )
        self._set_root_header(env, "content-security-policy", shuffled)
        assert _run(env)["status"] == "ok"

    def test_missing_cache_header_rejected(self, env):
        victim = (PAGES_BASE, mon.SERVING_IMAGE_PATH)
        headers, body = env["host"].responses[victim]
        headers = {k: v for k, v in headers.items() if k != "cache-control"}
        env["host"].responses[victim] = (headers, body)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "CACHE_HEADER"

    # --- R1: exact-set CSP drift detection --------------------------------

    def test_added_csp_directive_rejected(self, env):
        self._set_root_header(env, "content-security-policy", CSP + "; worker-src 'self'")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"
        assert "worker-src" in str(e.value)

    def test_duplicate_csp_directive_rejected(self, env):
        self._set_root_header(env, "content-security-policy", CSP + "; script-src 'self'")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"
        assert "duplicate" in str(e.value)

    def test_upgrade_insecure_requests_with_value_rejected(self, env):
        self._set_root_header(
            env,
            "content-security-policy",
            CSP.replace("upgrade-insecure-requests", "upgrade-insecure-requests 'self'"),
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_empty_csp_segment_rejected(self, env):
        self._set_root_header(env, "content-security-policy", CSP + ";")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"
        assert "empty" in str(e.value)

    # --- R1: exact-set Permissions-Policy drift detection -----------------

    def test_added_pp_feature_rejected(self, env):
        self._set_root_header(env, "permissions-policy", PP + ", browsing-topics=*")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_added_wellformed_pp_feature_rejected(self, env):
        self._set_root_header(env, "permissions-policy", PP + ", midi=()")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"
        assert "mismatch" in str(e.value)

    def test_duplicate_pp_entry_rejected(self, env):
        self._set_root_header(env, "permissions-policy", PP + ", usb=()")
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"
        assert "duplicate" in str(e.value)

    def test_notserial_substring_confusion_rejected(self, env):
        tampered = PP.replace("serial=(self)", "notserial=(self)")
        self._set_root_header(env, "permissions-policy", tampered)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_serial_suffix_confusion_rejected(self, env):
        tampered = PP.replace("serial=(self)", "serial=(self)extra")
        self._set_root_header(env, "permissions-policy", tampered)
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        assert e.value.category == "SECURITY_HEADER"

    def test_pp_whitespace_and_order_variant_accepted(self, env):
        reordered = (
            "usb=() ,  fullscreen=(self), serial=( self ), payment=(), "
            "microphone=(), camera=(), geolocation=()"
        )
        self._set_root_header(env, "permissions-policy", reordered)
        assert _run(env)["status"] == "ok"


# ---------------------------------------------------------------------------
# 5. Workflow contract
# ---------------------------------------------------------------------------

RAW_WF = WORKFLOW_PATH.read_text(encoding="utf-8")
# Directive-only view: comment lines are documentation, not contract surface.
WF_CODE = "\n".join(
    line for line in RAW_WF.splitlines() if not line.lstrip().startswith("#")
)
WF = yaml.safe_load(RAW_WF)
TRIGGERS = WF.get("on") or WF.get(True)


class TestWorkflowContract:
    def test_only_allowed_triggers(self):
        assert sorted(TRIGGERS) == ["pull_request", "push", "schedule", "workflow_dispatch"]

    def test_no_pull_request_target(self):
        assert "pull_request_target" not in RAW_WF

    def test_schedule_cron(self):
        assert TRIGGERS["schedule"] == [{"cron": "23 */6 * * *"}]

    def test_push_restricted_to_main_paths(self):
        assert TRIGGERS["push"]["branches"] == ["main"]
        assert ".github/workflows/browser-installer-monitor.yml" in TRIGGERS["push"]["paths"]

    def test_dispatch_has_no_inputs(self):
        assert TRIGGERS["workflow_dispatch"] in ({}, None)

    def test_permissions_read_only(self):
        assert WF["permissions"] == {"contents": "read"}
        assert "write" not in RAW_WF.split("permissions:")[1].split("concurrency:")[0]

    def test_concurrency(self):
        assert WF["concurrency"]["group"] == "browser-installer-monitor"
        assert WF["concurrency"]["cancel-in-progress"] is False

    def test_monitor_job_not_on_pull_request(self):
        job = WF["jobs"]["monitor"]
        assert job["if"] == "github.event_name != 'pull_request'"
        assert job["needs"] == "contract-tests"

    def test_timeouts_set(self):
        for job in WF["jobs"].values():
            assert job["timeout-minutes"] == 15
            assert job["runs-on"] == "ubuntu-latest"

    def test_actions_pinned_to_expected_shas(self):
        uses = re.findall(r"uses:\s*(\S+)", RAW_WF)
        assert uses, "workflow must use actions"
        allowed = {
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b",
        }
        assert set(uses) == allowed
        for step in (s for j in WF["jobs"].values() for s in j["steps"] if "uses" in s):
            if "checkout" in step["uses"]:
                assert step["with"]["persist-credentials"] is False

    def test_no_secrets_curl_or_default(self):
        assert "secrets." not in WF_CODE
        assert "curl" not in WF_CODE and "wget" not in WF_CODE
        assert "continue-on-error" not in WF_CODE
        # No silent default for the activation state.
        assert "||" not in WF_CODE
        assert "${{ vars.PVA_INSTALL_HOST_MONITOR_STATE }}" in WF_CODE

    def test_no_deploy_release_or_dns_commands(self):
        lowered = WF_CODE.lower()
        for needle in ("pages deploy", "wrangler", "gh release", "dns", "easyname",
                       "upload-artifact", "cloudflare_api"):
            assert needle not in lowered, needle

    def test_pull_request_job_is_network_free(self):
        # The pull_request event can only ever run contract-tests (monitor is
        # gated by event_name); contract-tests runs pytest suites only.
        steps = WF["jobs"]["contract-tests"]["steps"]
        run_cmds = " ".join(s.get("run", "") for s in steps)
        assert "monitor_browser_installer.py" not in run_cmds
        assert "pytest" in run_cmds


# ---------------------------------------------------------------------------
# 6. CLI behavior
# ---------------------------------------------------------------------------


class TestCli:
    def test_missing_state_fails_before_any_network(self, monkeypatch, capsys):
        monkeypatch.delenv(mon.ACTIVATION_ENV_VAR, raising=False)
        rc = mon.main([])
        captured = capsys.readouterr()
        assert rc == 1
        err = json.loads(captured.err)
        assert err["category"] == "ACTIVATION"
        assert captured.out == ""

    def test_unknown_state_fails(self, monkeypatch, capsys):
        monkeypatch.setenv(mon.ACTIVATION_ENV_VAR, "maybe")
        rc = mon.main([])
        err = json.loads(capsys.readouterr().err)
        assert rc == 1 and err["category"] == "ACTIVATION"

    def test_success_report_shape(self, env):
        report = _run(env, state="disabled")
        for key in ("schema_version", "status", "release_tag", "release_manifest",
                    "release_image", "serving_manifest", "activation_state",
                    "active_hosts", "inactive_hosts", "hosts",
                    "started_at", "completed_at"):
            assert key in report, key
        assert report["status"] == "ok"
        assert report["release_tag"] == "onboarding-v0.1.0"
        assert report["activation_state"] == "disabled"
        assert report["inactive_hosts"] == ["stable-install"]
        body = json.dumps(report)
        assert "gho_" not in body and "Bearer" not in body

    def test_error_has_category_host_path(self, env):
        env["host"].responses[(PAGES_BASE, "/")] = mon.MonitorError(
            "HTTP_STATUS", "HTTP 500", "pages-host", "/"
        )
        with pytest.raises(mon.MonitorError) as e:
            _run(env)
        d = e.value.as_dict()
        assert set(d) == {"category", "host", "path", "message"}
