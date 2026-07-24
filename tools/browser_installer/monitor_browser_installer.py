#!/usr/bin/env python3
"""Fail-closed monitor for the PVAutonomy browser-installer delivery.

ADR-0004 §6.2 (pvautonomy-config @ 7c73d6ca) — host-parameterized monitoring:

* verifies the canonical GitHub-Release assets against the existing trusted
  pins (``release-pins/onboarding-0.1.0.json``);
* derives the expected same-origin serving manifest with the existing exact
  single byte substitution (round-trip proven);
* verifies every ACTIVE host's delivered installer files, serving manifest,
  factory image, security headers, cache headers, and static HTML contract
  against the checked-out canonical repository state;
* exits nonzero with a clear category on ANY deviation.

Hosts are fixed in the versioned ``monitor-targets.json``. The stable host
``install.pvautonomy.com`` stays INACTIVE until the WP3-N1B gate flips the
repository variable ``PVA_INSTALL_HOST_MONITOR_STATE`` to ``enabled`` — the
environment value can only switch the pinned host on or off, never supply a
host name. A missing, empty, or unknown state is itself a failure
(fail-closed; no default, no coercion).

The monitor detects and reports drift; it never repairs, retries, mutates,
stores a firmware binary in the repository, or executes anything it fetched.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import http.client
import importlib.util
import json
import os
import posixpath
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
DEFAULT_PINS = TOOL_DIR / "release-pins" / "onboarding-0.1.0.json"
DEFAULT_TARGETS = TOOL_DIR / "monitor-targets.json"

ACTIVATION_ENV_VAR = "PVA_INSTALL_HOST_MONITOR_STATE"
ALLOWED_STATES = ("disabled", "enabled")
EXPECTED_TARGETS = (
    ("pages-production", "https://pvautonomy-installer.pages.dev", True),
    ("stable-install", "https://install.pvautonomy.com", False),
)

USER_AGENT = "pvautonomy-m1-monitor/1.0"
TIMEOUT_S = 30
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # hard cap; largest legit file is the image

JS_MIME = {"text/javascript", "application/javascript"}
BIN_MIME = {"application/octet-stream", "application/macbinary", "application/x-binary"}

SCHEMA_VERSION = 1


def _load_bundle_module():
    spec = importlib.util.spec_from_file_location(
        "build_verified_pages_bundle", TOOL_DIR / "build_verified_pages_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("build_verified_pages_bundle", module)
    spec.loader.exec_module(module)
    return module


bundle = _load_bundle_module()


class MonitorError(Exception):
    """Fail-closed monitor failure with a stable category."""

    def __init__(self, category: str, message: str, host: str = "-", path: str = "-"):
        super().__init__(message)
        self.category = category
        self.host = host
        self.path = path

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "host": self.host,
            "path": self.path,
            "message": str(self),
        }


# ---------------------------------------------------------------------------
# Config loader (strict) + activation
# ---------------------------------------------------------------------------


def load_targets(path: Path) -> list[dict]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MonitorError("CONFIG", f"targets file unreadable: {exc}") from exc
    try:
        return _validate_targets(raw)
    except MonitorError:
        raise
    except (TypeError, AttributeError, KeyError, ValueError) as exc:
        # Arbitrary invalid JSON shapes must not escape as raw tracebacks.
        raise MonitorError("CONFIG", f"invalid targets structure: {exc!r}") from exc


def _validate_targets(raw) -> list[dict]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "activation_env_var",
        "targets",
    }:
        raise MonitorError("CONFIG", f"unexpected top-level keys: {sorted(raw)}")
    if raw["schema_version"] != SCHEMA_VERSION:
        raise MonitorError("CONFIG", f"unsupported schema_version {raw['schema_version']!r}")
    if raw["activation_env_var"] != ACTIVATION_ENV_VAR:
        raise MonitorError("CONFIG", f"unexpected activation_env_var {raw['activation_env_var']!r}")
    targets = raw["targets"]
    if not isinstance(targets, list) or len(targets) != len(EXPECTED_TARGETS):
        raise MonitorError("CONFIG", "targets must list exactly the two pinned hosts")
    seen = []
    for entry, (name, base_url, always) in zip(targets, EXPECTED_TARGETS):
        if not isinstance(entry, dict) or set(entry) != {"name", "base_url", "always_active"}:
            raise MonitorError("CONFIG", f"unexpected target keys: {entry!r}")
        if entry["name"] != name or entry["always_active"] is not always:
            raise MonitorError("CONFIG", f"unexpected target identity: {entry!r}")
        if not isinstance(entry["base_url"], str):
            raise MonitorError("CONFIG", f"base_url must be a string: {entry['base_url']!r}")
        parsed = urllib.parse.urlparse(entry["base_url"])
        if (
            entry["base_url"] != base_url
            or parsed.scheme != "https"
            or parsed.port is not None
            or parsed.username or parsed.password
            or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise MonitorError("CONFIG", f"unexpected base_url: {entry['base_url']!r}")
        seen.append(dict(entry))
    return seen


def resolve_activation(state: str | None, targets: list[dict]) -> tuple[list[dict], list[dict]]:
    """Map the raw environment value to active/inactive host lists."""
    if state is None or state == "":
        raise MonitorError(
            "ACTIVATION",
            f"{ACTIVATION_ENV_VAR} is missing/empty — refusing to run (no default)",
        )
    if state not in ALLOWED_STATES:
        raise MonitorError("ACTIVATION", f"unknown activation state {state!r}")
    active = [t for t in targets if t["always_active"] or state == "enabled"]
    inactive = [t for t in targets if t not in active]
    return active, inactive


# ---------------------------------------------------------------------------
# Host HTTP fetcher (no redirects, TLS verified, bounded, GET only)
# ---------------------------------------------------------------------------


class _RedirectRefused(Exception):
    def __init__(self, code, target):
        self.code, self.target = code, target


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _RedirectRefused(code, newurl)


class HostFetcher:
    """GET-only, redirect-refusing, TLS-verified fetcher for monitored hosts."""

    def __init__(self, timeout: int = TIMEOUT_S):
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def get(self, base_url: str, path: str) -> tuple[dict, bytes]:
        url = base_url + path
        host = urllib.parse.urlparse(url).hostname or base_url
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise MonitorError(
                        "HTTP_STATUS", f"HTTP {response.status}", host, path
                    )
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise MonitorError("SIZE", "response exceeds hard cap", host, path)
                headers = {k.lower(): v for k, v in response.headers.items()}
                return headers, body
        except _RedirectRefused as exc:
            raise MonitorError(
                "REDIRECT", f"redirect {exc.code} -> {exc.target}", host, path
            ) from exc
        except urllib.error.HTTPError as exc:
            raise MonitorError("HTTP_STATUS", f"HTTP {exc.code}", host, path) from exc
        except urllib.error.URLError as exc:
            raise MonitorError("DNS_OR_TLS", f"{exc.reason}", host, path) from exc
        except TimeoutError as exc:
            raise MonitorError("DNS_OR_TLS", "timeout", host, path) from exc


# ---------------------------------------------------------------------------
# Release verification (reuses the H1 trusted pins + fetch + derivation)
# ---------------------------------------------------------------------------


def _fetch_release_asset(release_fetcher, url: str, size: int, sha256: str) -> bytes:
    """Fetch one release asset with a complete structured error boundary.

    Every expectable network/verification failure becomes a MonitorError —
    no raw urllib/http exception (and no traceback) may escape the monitor
    for operational failures. HTTPError is handled before URLError because
    it inherits from it.
    """
    host = urllib.parse.urlparse(url).hostname or "-"
    path = urllib.parse.urlparse(url).path or url
    try:
        return release_fetcher.fetch(url, size, sha256)
    except bundle.BundleError as exc:
        category = "REDIRECT" if str(exc).startswith("redirect") else "RELEASE_IDENTITY"
        raise MonitorError(category, str(exc), host, path) from exc
    except urllib.error.HTTPError as exc:
        raise MonitorError("HTTP_STATUS", f"HTTP {exc.code}", host, path) from exc
    except urllib.error.URLError as exc:
        raise MonitorError("DNS_OR_TLS", f"{exc.reason}", host, path) from exc
    except (TimeoutError, ConnectionError, http.client.HTTPException) as exc:
        raise MonitorError(
            "DNS_OR_TLS", f"{exc.__class__.__name__}: {exc}", host, path
        ) from exc
    except OSError as exc:
        raise MonitorError(
            "DNS_OR_TLS", f"{exc.__class__.__name__}: {exc}", host, path
        ) from exc


def verify_release(pins: dict, release_fetcher) -> dict:
    """Verify both canonical release assets and derive the serving manifest."""
    manifest = _fetch_release_asset(
        release_fetcher, pins["manifest_url"], pins["manifest_size"], pins["manifest_sha256"]
    )
    image = _fetch_release_asset(
        release_fetcher, pins["image_url"], pins["image_size"], pins["image_sha256"]
    )
    try:
        # Defense in depth: re-verify both assets independently of the fetcher.
        bundle._verify_bytes(
            manifest, pins["manifest_size"], pins["manifest_sha256"], "release manifest"
        )
        bundle._verify_bytes(image, pins["image_size"], pins["image_sha256"], "release image")
        serving = bundle.derive_serving_manifest(manifest, pins)
    except bundle.BundleError as exc:
        raise MonitorError("RELEASE_IDENTITY", str(exc)) from exc
    round_trip = serving.replace(
        pins["relative_image_token"].encode(),
        pins["absolute_image_url_token"].encode(),
        1,
    )
    if round_trip != manifest:
        raise MonitorError("RELEASE_IDENTITY", "serving round-trip mismatch")
    return {
        "manifest": manifest,
        "image": image,
        "serving": serving,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "serving_sha256": hashlib.sha256(serving).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Header verification
# ---------------------------------------------------------------------------

# The delivered security policies must match these EXACT sets — a missing,
# duplicated, weakened, or ADDED directive/feature is drift and fails closed.
EXPECTED_CSP = {
    "default-src": "'none'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self' data:",
    "connect-src": "'self'",
    "manifest-src": "'self'",
    "base-uri": "'none'",
    "form-action": "'none'",
    "frame-ancestors": "'none'",
    "object-src": "'none'",
    "upgrade-insecure-requests": "",  # valueless directive
}
EXPECTED_PP = frozenset(
    {
        "serial=(self)",
        "usb=()",
        "geolocation=()",
        "camera=()",
        "microphone=()",
        "payment=()",
        "fullscreen=(self)",
    }
)
_PP_ENTRY_RE = re.compile(r"^[a-z][a-z-]*=\((?:self)?\)$")


def _parse_csp(value: str, host: str, path: str) -> list[tuple[str, str]]:
    """Parse a CSP into (name, value) pairs, preserving duplicates."""
    entries: list[tuple[str, str]] = []
    for segment in value.split(";"):
        normalized = " ".join(segment.split())
        if not normalized:
            raise MonitorError(
                "SECURITY_HEADER", "malformed CSP: empty directive segment", host, path
            )
        name, _, rest = normalized.partition(" ")
        entries.append((name.lower(), rest))
    return entries


def verify_security_headers(headers: dict, host: str, path: str) -> None:
    csp_raw = headers.get("content-security-policy")
    if not csp_raw:
        raise MonitorError("SECURITY_HEADER", "missing Content-Security-Policy", host, path)
    if "unsafe-inline" in csp_raw or "unsafe-eval" in csp_raw:
        raise MonitorError("SECURITY_HEADER", "unsafe-inline/unsafe-eval present", host, path)
    entries = _parse_csp(csp_raw, host, path)
    names = [name for name, _ in entries]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise MonitorError(
            "SECURITY_HEADER", f"duplicate CSP directive(s): {sorted(duplicates)}", host, path
        )
    unknown = set(names) - set(EXPECTED_CSP)
    if unknown:
        raise MonitorError(
            "SECURITY_HEADER", f"unexpected CSP directive(s): {sorted(unknown)}", host, path
        )
    missing = set(EXPECTED_CSP) - set(names)
    if missing:
        raise MonitorError(
            "SECURITY_HEADER", f"missing CSP directive(s): {sorted(missing)}", host, path
        )
    for name, value in entries:
        if value != EXPECTED_CSP[name]:
            raise MonitorError(
                "SECURITY_HEADER",
                f"CSP {name} is {value!r}, expected {EXPECTED_CSP[name]!r}",
                host,
                path,
            )

    pp_raw = headers.get("permissions-policy")
    if not pp_raw:
        raise MonitorError("SECURITY_HEADER", "missing Permissions-Policy", host, path)
    tokens: list[str] = []
    for part in pp_raw.split(","):
        token = part.strip().replace(" ", "")
        if not token:
            raise MonitorError(
                "SECURITY_HEADER", "malformed Permissions-Policy: empty entry", host, path
            )
        if token.startswith("serial=") and token != "serial=(self)":
            raise MonitorError(
                "SECURITY_HEADER", f"Permissions-Policy disables serial: {token}", host, path
            )
        if not _PP_ENTRY_RE.match(token):
            raise MonitorError(
                "SECURITY_HEADER", f"malformed Permissions-Policy entry: {token!r}", host, path
            )
        tokens.append(token)
    duplicate_pp = {t for t in tokens if tokens.count(t) > 1}
    if duplicate_pp:
        raise MonitorError(
            "SECURITY_HEADER",
            f"duplicate Permissions-Policy entries: {sorted(duplicate_pp)}",
            host,
            path,
        )
    if set(tokens) != EXPECTED_PP:
        raise MonitorError(
            "SECURITY_HEADER",
            f"Permissions-Policy set mismatch: {sorted(set(tokens) ^ EXPECTED_PP)}",
            host,
            path,
        )

    if (headers.get("x-content-type-options") or "").lower() != "nosniff":
        raise MonitorError("SECURITY_HEADER", "missing X-Content-Type-Options: nosniff", host, path)
    if headers.get("referrer-policy") != "strict-origin-when-cross-origin":
        raise MonitorError("SECURITY_HEADER", "unexpected Referrer-Policy", host, path)
    if (headers.get("x-frame-options") or "").upper() != "DENY":
        raise MonitorError("SECURITY_HEADER", "missing X-Frame-Options: DENY", host, path)
    hsts = " ".join((headers.get("strict-transport-security") or "").split())
    if hsts != "max-age=15552000":
        raise MonitorError("SECURITY_HEADER", f"unexpected HSTS {hsts!r}", host, path)


def verify_cache_header(headers: dict, host: str, path: str) -> None:
    cache = (headers.get("cache-control") or "").lower()
    parts = {p.strip() for p in cache.split(",")}
    for needed in ("public", "max-age=31536000", "immutable"):
        if needed not in parts:
            raise MonitorError(
                "CACHE_HEADER", f"Cache-Control {cache!r} missing {needed}", host, path
            )


# ---------------------------------------------------------------------------
# HTML contract (independent, fail-closed)
# ---------------------------------------------------------------------------

RELEASE_LINKS = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/tag/onboarding-v0.1.0",
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/onboarding-v0.1.0/edge101-onboarding-0.1.0.factory.bin",
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/onboarding-v0.1.0/edge101-onboarding-0.1.0.factory.bin.sha256",
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/onboarding-v0.1.0/edge101-onboarding-0.1.0.manifest.json",
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/onboarding-v0.1.0/edge101-onboarding-0.1.0.metadata.json",
)
SERVING_MANIFEST_PATH = "/firmware/onboarding-0.1.0/edge101-onboarding-0.1.0.manifest.json"
SERVING_IMAGE_PATH = "/firmware/onboarding-0.1.0/edge101-onboarding-0.1.0.factory.bin"
IMAGE_SHA256 = "879afa1528c97548ed0ed82a859f408611a6c871fc3a97492f7d52dcb01cb9c1"


class _HtmlFacts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.buttons = []
        self.script_srcs = []
        self.inline_scripts = 0
        self.style_tags = 0
        self.style_attrs = 0
        self.event_attrs = 0
        self.forms = 0
        self.inputs = 0
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for name, _ in attrs:
            if name == "style":
                self.style_attrs += 1
            if name.startswith("on"):
                self.event_attrs += 1
        if tag == "esp-web-install-button":
            self.buttons.append(a)
        elif tag == "script":
            if a.get("src"):
                self.script_srcs.append(a["src"])
            else:
                self.inline_scripts += 1
        elif tag == "style":
            self.style_tags += 1
        elif tag == "form":
            self.forms += 1
        elif tag in ("input", "textarea", "select"):
            self.inputs += 1

    def handle_data(self, data):
        self.text.append(data)


def verify_html_contract(body: bytes, host: str) -> None:
    page = body.decode("utf-8")
    facts = _HtmlFacts()
    facts.feed(page)
    text = " ".join(facts.text)

    def fail(msg):
        raise MonitorError("CONTENT", msg, host, "/")

    if len(facts.buttons) != 1:
        fail(f"expected exactly one install button, found {len(facts.buttons)}")
    if facts.buttons[0].get("manifest") != SERVING_MANIFEST_PATH:
        fail("install button manifest attribute is not the same-origin serving path")
    if not re.search(r"\b0\.1\.0\b", text):
        fail("version 0.1.0 not visible")
    if IMAGE_SHA256 not in text:
        fail("full image SHA-256 not visible")
    for link in RELEASE_LINKS:
        if link not in page:
            fail(f"canonical release link missing: {link}")
    for src in facts.script_srcs:
        if src.startswith(("http:", "https:", "//")):
            fail(f"external runtime script source: {src}")
    if facts.inline_scripts or facts.style_tags or facts.style_attrs or facts.event_attrs:
        fail("inline script/style/event-handler present")
    if facts.forms or facts.inputs:
        fail("forms or inputs present")
    lowered = page.lower()
    for needle in ("fetch(", "xmlhttprequest", "sendbeacon", "gtag(", "plausible"):
        if needle in lowered:
            fail(f"telemetry/network call present: {needle}")
    for needle in ("sign in", "log in", "checkout", "select plan", "choose your plan"):
        if needle in lowered:
            fail(f"login/payment/mode control present: {needle}")
    if "managed" not in lowered or ("open-source" not in lowered and "open source" not in lowered):
        fail("Managed/Open-Source single-surface statement missing")
    if "not been validated on real hardware" not in lowered or "customer-ready" not in lowered:
        fail("technical-preview framing missing")
    for needle in ("firmware.ota.bin", "ota.md5", "/latest/"):
        if needle in lowered:
            fail(f"forbidden reference: {needle}")


# ---------------------------------------------------------------------------
# Host verification
# ---------------------------------------------------------------------------


def _vendor_modules(web_dir: Path) -> list[str]:
    imp = re.compile(r"""(?:\bfrom|\bimport)\s*(?:\(\s*)?["'`]([^"'`]+)["'`]""")
    seen: set[str] = set()
    stack = ["install-button.js"]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for target in imp.findall((web_dir / cur).read_text(encoding="utf-8")):
            if target.startswith(("http:", "https:", "data:", "blob:", "//")):
                raise MonitorError("CONTENT", f"non-relative vendor import {target!r} in {cur}")
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(cur), target))
            if resolved.startswith(".."):
                raise MonitorError("CONTENT", f"vendor import escapes web/: {target!r} in {cur}")
            if (web_dir / resolved).is_file():
                stack.append(resolved)
    return sorted(seen)


def verify_host(target: dict, pins: dict, release: dict, fetcher) -> dict:
    base = target["base_url"]
    host = urllib.parse.urlparse(base).hostname
    installer_dir = REPO_ROOT / "installer"
    web_dir = installer_dir / "vendor/esp-web-tools/10.4.0/web"
    checked = 0

    def get_checked(path, expected_bytes, allowed_mimes, cache=False, security=False):
        nonlocal checked
        headers, body = fetcher.get(base, path)
        mime = (headers.get("content-type") or "").split(";")[0].strip().lower()
        if allowed_mimes is not None and mime not in allowed_mimes:
            raise MonitorError("MIME", f"unexpected content-type {mime!r}", host, path)
        if expected_bytes is not None:
            if len(body) != len(expected_bytes):
                raise MonitorError(
                    "SIZE", f"{len(body)} bytes != expected {len(expected_bytes)}", host, path
                )
            if hashlib.sha256(body).hexdigest() != hashlib.sha256(expected_bytes).hexdigest():
                raise MonitorError("SHA256", "content hash mismatch", host, path)
            if body != expected_bytes:
                raise MonitorError("CONTENT", "byte mismatch", host, path)
        if security:
            verify_security_headers(headers, host, path)
        if cache:
            verify_cache_header(headers, host, path)
        checked += 1
        return headers, body

    # Root page: byte-identical to the canonical repository page + contract.
    index_bytes = (installer_dir / "index.html").read_bytes()
    _, root_body = get_checked("/", index_bytes, {"text/html"}, security=True)
    verify_html_contract(root_body, host)

    # Assets.
    get_checked("/assets/installer.css", (installer_dir / "assets/installer.css").read_bytes(), {"text/css"})
    get_checked(
        "/assets/serial-support.js",
        (installer_dir / "assets/serial-support.js").read_bytes(),
        JS_MIME,
    )

    # Vendor runtime graph (26 reachable modules incl. install-button.js).
    modules = _vendor_modules(web_dir)
    for name in modules:
        vendor_path = f"/vendor/esp-web-tools/10.4.0/web/{name}"
        cache = name == "install-button.js"
        get_checked(vendor_path, (web_dir / name).read_bytes(), JS_MIME, cache=cache)

    # Serving manifest: byte-identical to the derived expectation + structure.
    _, manifest_body = get_checked(
        SERVING_MANIFEST_PATH, release["serving"], {"application/json"}, cache=True
    )
    doc = json.loads(manifest_body.decode("utf-8"))
    part = doc["builds"][0]["parts"][0]
    if (
        doc.get("version") != "0.1.0"
        or len(doc.get("builds", [])) != 1
        or len(doc["builds"][0].get("parts", [])) != 1
        or doc["builds"][0].get("chipFamily") != "ESP32"
        or part.get("offset") != 0
        or doc.get("new_install_prompt_erase") is not False
        or part.get("path") != pins["relative_image_token"]
    ):
        raise MonitorError("CONTENT", "serving manifest structure mismatch", host, SERVING_MANIFEST_PATH)
    lowered = manifest_body.decode("utf-8").lower()
    if "github.com" in lowered or "/latest/" in lowered or "ota" in lowered:
        raise MonitorError("CONTENT", "forbidden reference in serving manifest", host, SERVING_MANIFEST_PATH)

    # Factory image: byte-identical to the canonical release image.
    get_checked(SERVING_IMAGE_PATH, release["image"], BIN_MIME, cache=True)

    return {
        "base_url": base,
        "paths_checked": checked,
        "root_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "manifest_sha256": release["serving_sha256"],
        "image_sha256": release["image_sha256"],
        "security_headers": "ok",
        "cache_headers": "ok",
        "tls": "verified",
    }


# ---------------------------------------------------------------------------
# Run + CLI
# ---------------------------------------------------------------------------


def run_monitor(
    state: str | None,
    targets_path: Path = DEFAULT_TARGETS,
    pins_path: Path = DEFAULT_PINS,
    release_fetcher=None,
    host_fetcher=None,
) -> dict:
    started = _dt.datetime.now(_dt.timezone.utc)
    targets = load_targets(targets_path)
    active, inactive = resolve_activation(state, targets)
    try:
        pins = bundle.load_pins(pins_path)
    except (
        bundle.PinError,
        OSError,
        UnicodeDecodeError,
        ValueError,  # includes json.JSONDecodeError
        TypeError,
    ) as exc:
        raise MonitorError("CONFIG", f"trusted pins invalid: {exc!r}") from exc

    release_fetcher = release_fetcher or bundle.UrlFetcher(pins["redirect_host_allowlist"])
    host_fetcher = host_fetcher or HostFetcher()

    # Canonical release identity FIRST; hosts are not contacted if it fails.
    release = verify_release(pins, release_fetcher)

    host_reports = [verify_host(t, pins, release, host_fetcher) for t in active]

    completed = _dt.datetime.now(_dt.timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "release_tag": pins["release_tag"],
        "release_manifest": {"size": pins["manifest_size"], "sha256": release["manifest_sha256"]},
        "release_image": {"size": pins["image_size"], "sha256": release["image_sha256"]},
        "serving_manifest": {"size": len(release["serving"]), "sha256": release["serving_sha256"]},
        "activation_state": state,
        "active_hosts": [t["name"] for t in active],
        "inactive_hosts": [t["name"] for t in inactive],
        "hosts": host_reports,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS)
    args = parser.parse_args(argv)
    state = os.environ.get(ACTIVATION_ENV_VAR)
    try:
        report = run_monitor(state, args.targets, args.pins)
    except MonitorError as exc:
        json.dump(exc.as_dict(), sys.stderr, indent=2)
        sys.stderr.write("\n")
        return 1
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
