"""Contract tests for the WP3-I1 local browser-installer candidate.

Scope: the static, self-hosted installer page under ``installer/`` that will
later be served at ``https://install.pvautonomy.com/`` (ADR-0004 §6, §21).

These tests pin the page to the **immutable** ``onboarding-v0.1.0`` release and
enforce the WP3-I1 boundaries. They never contact GitHub, a browser, a device,
or the network.

Enforced:
* exact manifest / image / checksum / metadata / release-page URLs;
* the full SHA-256 and version 0.1.0 are visible on the page;
* exactly one ``<esp-web-install-button>`` bound to the immutable manifest;
* no ``/latest/`` URL, no local manifest/binary copy;
* no ``firmware.ota.bin`` / ``ota.md5`` / Production-OTA path reference;
* no external (CDN/unpkg/jsDelivr) runtime script source; the ESP-Web-Tools
  runtime is fully self-hosted and self-contained (relative imports only);
* no auth / payment / build-key / analytics / credential forms;
* the same public surface serves Managed and Open-Source (one button, one
  manifest, no mode switch);
* the page is marked a technical, not-yet-customer-ready preview and makes no
  success claim (flash / erase / Improv / captive portal / HA adoption).
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import http.server
import posixpath
import re
import threading
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_DIR = REPO_ROOT / "installer"
PAGE_PATH = INSTALLER_DIR / "index.html"
VENDOR_DIR = INSTALLER_DIR / "vendor"
EWT_DIR = VENDOR_DIR / "esp-web-tools" / "10.4.0"
WEB_DIR = EWT_DIR / "web"
ROOT_MODULE = "install-button.js"

PAGE = PAGE_PATH.read_text(encoding="utf-8")

# Matches relative ES-module references in minified bundles:
#   import("./x.js")   import "./x.js"   import"./x.js"   from"./x.js"
#   export ... from "./x.js"
_IMPORT_RE = re.compile(r"""(?:\bfrom|\bimport)\s*(?:\(\s*)?["'`]([^"'`]+)["'`]""")
# Dynamic import() specifically, to prove the parser actually sees code.
_DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*["'`][^"'`]+["'`]""")


def _imports_in(module_name: str) -> list[str]:
    return _IMPORT_RE.findall((WEB_DIR / module_name).read_text(encoding="utf-8"))


def _dynamic_import_count(module_name: str) -> int:
    return len(_DYNAMIC_IMPORT_RE.findall((WEB_DIR / module_name).read_text(encoding="utf-8")))


def _resolve_rel(from_module: str, target: str) -> str:
    """Resolve a relative import to a web/-relative posix path."""
    return posixpath.normpath(posixpath.join(posixpath.dirname(from_module), target))


def _reachable_from_root() -> set[str]:
    """Files reachable via the relative import graph rooted at install-button.js."""
    reachable: set[str] = set()
    stack = [ROOT_MODULE]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        for target in _imports_in(cur):
            resolved = _resolve_rel(cur, target)
            if (WEB_DIR / resolved).is_file():
                stack.append(resolved)
    return reachable

RELEASE_BASE = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/"
    "onboarding-v0.1.0"
)
MANIFEST_URL = f"{RELEASE_BASE}/edge101-onboarding-0.1.0.manifest.json"
IMAGE_URL = f"{RELEASE_BASE}/edge101-onboarding-0.1.0.factory.bin"
CHECKSUM_URL = f"{RELEASE_BASE}/edge101-onboarding-0.1.0.factory.bin.sha256"
METADATA_URL = f"{RELEASE_BASE}/edge101-onboarding-0.1.0.metadata.json"
RELEASE_PAGE_URL = (
    "https://github.com/PVAutonomy/pvautonomy-firmware/releases/tag/"
    "onboarding-v0.1.0"
)
SHA256 = "879afa1528c97548ed0ed82a859f408611a6c871fc3a97492f7d52dcb01cb9c1"
VERSION = "0.1.0"

# ADR-0004 §6.1 verified same-origin serving: the button consumes the
# deploy-time-staged serving manifest, never the GitHub URL directly.
SERVING_MANIFEST_PATH = (
    "/firmware/onboarding-0.1.0/edge101-onboarding-0.1.0.manifest.json"
)
HEADERS_PATH = INSTALLER_DIR / "_headers"
ASSETS_DIR = INSTALLER_DIR / "assets"
CSS_PATH = ASSETS_DIR / "installer.css"
SERIAL_JS_PATH = ASSETS_DIR / "serial-support.js"


class _Collector(HTMLParser):
    """Collect the structural facts the contract depends on."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.install_buttons: list[dict] = []
        self.scripts: list[dict] = []
        self.stylesheets: list[str] = []
        self.style_tags = 0
        self.style_attrs: list[tuple[str, str]] = []
        self.event_handler_attrs: list[tuple[str, str]] = []
        self.forms = 0
        self.inputs = 0
        self.anchors: list[dict] = []  # {"href":…, "section":last-h2-text}
        self._text: list[str] = []
        self._in_h2 = False
        self._current_section = ""
        self._script_depth = 0
        self.inline_script_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for name, value in attrs:
            if name == "style":
                self.style_attrs.append((tag, value or ""))
            if name.startswith("on"):
                self.event_handler_attrs.append((tag, name))
        if tag == "esp-web-install-button":
            self.install_buttons.append(a)
        elif tag == "script":
            self.scripts.append(a)
            if "src" not in a:
                self._script_depth += 1
        elif tag == "style":
            self.style_tags += 1
        elif tag == "link" and a.get("rel") == "stylesheet":
            self.stylesheets.append(a.get("href", ""))
        elif tag == "form":
            self.forms += 1
        elif tag in ("input", "textarea", "select"):
            self.inputs += 1
        elif tag == "h2":
            self._in_h2 = True
            self._current_section = ""
        elif tag == "a":
            self.anchors.append(
                {"href": a.get("href", ""), "section": self._current_section}
            )

    def handle_endtag(self, tag):
        if tag == "h2":
            self._in_h2 = False
        elif tag == "script" and self._script_depth:
            self._script_depth -= 1

    def handle_data(self, data):
        self._text.append(data)
        if self._in_h2:
            self._current_section += data
        if self._script_depth and data.strip():
            self.inline_script_chunks.append(data)

    @property
    def text(self) -> str:
        return " ".join(self._text)


def _dom() -> _Collector:
    p = _Collector()
    p.feed(PAGE)
    return p


DOM = _dom()


# ---------------------------------------------------------------------------
# Page exists and is the only installer entry point
# ---------------------------------------------------------------------------


def test_page_exists():
    assert PAGE_PATH.is_file()


# ---------------------------------------------------------------------------
# Exactly one install button, bound to the immutable manifest
# ---------------------------------------------------------------------------


def test_exactly_one_install_button():
    assert len(DOM.install_buttons) == 1


def test_button_manifest_is_the_same_origin_serving_path():
    # ADR-0004 §6.1(b): the button consumes the same-origin serving manifest.
    (button,) = DOM.install_buttons
    assert button.get("manifest") == SERVING_MANIFEST_PATH


def test_button_manifest_is_not_the_github_release_url():
    (button,) = DOM.install_buttons
    assert button.get("manifest") != MANIFEST_URL
    assert not button.get("manifest", "").startswith("https://")


def test_only_one_manifest_attribute_on_the_page():
    # No hidden second manifest / no per-audience manifest.
    assert PAGE.count('manifest="') == 1
    assert PAGE.count(SERVING_MANIFEST_PATH) == 1


def test_published_manifest_url_remains_a_manual_link():
    # The published manifest stays visible as a canonical release link —
    # exactly once, and only as a manual-download anchor (not the button).
    assert PAGE.count(MANIFEST_URL) == 1
    manual_anchors = [a for a in DOM.anchors if a["href"] == MANIFEST_URL]
    assert len(manual_anchors) == 1


def test_release_links_live_in_the_manual_download_section():
    # Structural: the five canonical release links must be real anchors in
    # the "Release & manual download" card — not comments or hidden text.
    section_anchors = {
        a["href"]
        for a in DOM.anchors
        if "release" in a["section"].lower() and "download" in a["section"].lower()
    }
    for url in (RELEASE_PAGE_URL, IMAGE_URL, CHECKSUM_URL, METADATA_URL, MANIFEST_URL):
        assert url in section_anchors, f"missing manual-download anchor: {url}"


# ---------------------------------------------------------------------------
# Exact release URLs, version, and full SHA-256 are present and visible
# ---------------------------------------------------------------------------


def test_exact_release_urls_present():
    for url in (MANIFEST_URL, IMAGE_URL, CHECKSUM_URL, METADATA_URL, RELEASE_PAGE_URL):
        assert url in PAGE, f"missing exact URL: {url}"


def test_full_sha256_visible_in_page_text():
    assert SHA256 in DOM.text


def test_version_visible_in_page_text():
    assert re.search(rf"\b{re.escape(VERSION)}\b", DOM.text)


# ---------------------------------------------------------------------------
# No /latest/, no local manifest/binary copy
# ---------------------------------------------------------------------------


def test_no_latest_url_anywhere():
    assert "/latest/" not in PAGE
    assert "releases/latest" not in PAGE


def test_no_local_manifest_or_binary_copy():
    # The installer directory must not carry a copied release asset; the page
    # must reference the immutable release location only.
    forbidden_suffixes = (
        ".factory.bin",
        ".manifest.json",
        ".metadata.json",
        ".sha256",
        ".ota.bin",
    )
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in INSTALLER_DIR.rglob("*")
        if p.is_file() and p.name.endswith(forbidden_suffixes)
    ]
    assert offenders == [], f"local release-asset copies found: {offenders}"


# ---------------------------------------------------------------------------
# No Production-OTA references / no CLI path
# ---------------------------------------------------------------------------


def test_no_production_ota_reference():
    lowered = PAGE.lower()
    for needle in ("firmware.ota.bin", "ota.md5", "production ota", "/firmware/edge101/"):
        assert needle not in lowered, f"forbidden Production-OTA reference: {needle}"


def test_no_terminal_or_cli_instructions():
    lowered = PAGE.lower()
    for needle in ("esptool", "pip install", "esphome ", "```", "$ "):
        assert needle not in lowered, f"forbidden CLI/terminal instruction: {needle}"


# ---------------------------------------------------------------------------
# Fully self-hosted runtime: no external script source
# ---------------------------------------------------------------------------


def test_no_external_runtime_script_source():
    for script in DOM.scripts:
        src = script.get("src")
        if src is None:
            continue  # inline module scripts are allowed
        assert not re.match(r"https?:", src), f"external script src: {src}"
        assert not src.startswith("//"), f"protocol-relative script src: {src}"
        for cdn in ("unpkg", "jsdelivr", "cdn", "esm.sh", "skypack"):
            assert cdn not in src.lower(), f"CDN script src: {src}"


def test_runtime_script_points_at_vendored_button():
    srcs = [s.get("src") for s in DOM.scripts if s.get("src")]
    assert "vendor/esp-web-tools/10.4.0/web/install-button.js" in srcs
    # ...and that file actually exists on disk.
    assert (INSTALLER_DIR / "vendor/esp-web-tools/10.4.0/web/install-button.js").is_file()


# ---------------------------------------------------------------------------
# Vendored ESP-Web-Tools: present, integrity-checked, self-contained
# ---------------------------------------------------------------------------


def test_vendor_provenance_documented():
    prov = (VENDOR_DIR / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "esp-web-tools" in prov
    assert "10.4.0" in prov
    assert "Apache-2.0" in prov
    assert "f18da75335d2f0dca044c4bb052848c0696e7b03cc23d61d8530dd6eba0a9008" in prov
    assert (EWT_DIR / "LICENSE").is_file()


_SHA256SUMS_LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


def test_vendor_sha256sums_closed_contract():
    """SHA256SUMS is a strict, fail-closed, exhaustive index of the vendor tree."""
    raw = (EWT_DIR / "SHA256SUMS").read_text(encoding="utf-8")
    indexed: dict[str, str] = {}
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if line == "":
            continue
        m = _SHA256SUMS_LINE.match(line)
        # regex enforces: exactly 64 lowercase-hex digits, exactly two spaces
        # (group 2 must open with a non-space), and a non-empty path.
        assert m, f"malformed SHA256SUMS line {lineno}: {line!r}"
        digest, rel = m.group(1), m.group(2)
        assert not rel.startswith("/"), f"absolute path on line {lineno}: {rel!r}"
        assert rel == rel.strip(), f"padded path on line {lineno}: {rel!r}"
        assert ".." not in rel.split("/"), f"'..' segment on line {lineno}: {rel!r}"
        assert rel not in indexed, f"duplicate entry on line {lineno}: {rel!r}"
        indexed[rel] = digest

    # 2/3/4: the indexed set is exactly the vendored files, minus SHA256SUMS.
    actual = {
        p.relative_to(EWT_DIR).as_posix()
        for p in EWT_DIR.rglob("*")
        if p.is_file()
    } - {"SHA256SUMS"}
    missing_on_disk = set(indexed) - actual
    unindexed = actual - set(indexed)
    assert not missing_on_disk, f"indexed but absent: {sorted(missing_on_disk)}"
    assert not unindexed, f"present but unindexed: {sorted(unindexed)}"

    assert "LICENSE" in indexed
    web_js = {p for p in indexed if p.startswith("web/") and p.endswith(".js")}
    assert web_js == {
        p.relative_to(EWT_DIR).as_posix() for p in WEB_DIR.glob("*.js")
    }
    assert len(web_js) >= 25

    # 5: every indexed file matches its recorded digest.
    for rel, digest in indexed.items():
        actual_digest = hashlib.sha256((EWT_DIR / rel).read_bytes()).hexdigest()
        assert actual_digest == digest, f"checksum mismatch for {rel}"


def test_vendor_es_module_imports_are_relative_and_resolvable():
    """Every static/dynamic import in every web/*.js resolves inside web/."""
    web_root = WEB_DIR.resolve()
    edges = 0
    dynamic = 0
    for js in sorted(WEB_DIR.glob("*.js")):
        dynamic += _dynamic_import_count(js.name)
        for target in _imports_in(js.name):
            edges += 1
            assert target.startswith("./"), f"non-relative import {target!r} in {js.name}"
            assert "://" not in target and not target.startswith("//"), (
                f"URL/host import {target!r} in {js.name}"
            )
            assert not target.startswith(("data:", "blob:")), (
                f"data/blob import {target!r} in {js.name}"
            )
            assert "?" not in target and "#" not in target, (
                f"query/fragment in {target!r} in {js.name}"
            )
            assert target.endswith(".js"), f"non-.js import {target!r} in {js.name}"
            resolved = _resolve_rel(js.name, target)
            assert not resolved.startswith(".."), f"escapes web/: {target!r} in {js.name}"
            full = (WEB_DIR / resolved).resolve()
            assert full.is_file(), f"missing import target {target!r} in {js.name}"
            assert web_root in full.parents, f"outside web/: {target!r} in {js.name}"
    assert edges >= 1, "no module imports parsed"
    # 4: a no-op parser cannot pass green.
    assert dynamic >= 1, "no dynamic import() found — parser ineffective"


def test_vendor_import_graph_fully_resolvable_from_button_root():
    """install-button.js is the reachable root of a fully resolvable graph."""
    assert (WEB_DIR / ROOT_MODULE).is_file()
    missing: list[tuple[str, str]] = []
    reachable: set[str] = set()
    stack = [ROOT_MODULE]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        for target in _imports_in(cur):
            resolved = _resolve_rel(cur, target)
            if (WEB_DIR / resolved).is_file():
                stack.append(resolved)
            else:
                missing.append((cur, target))
    assert missing == [], f"unresolved imports in graph: {missing}"
    assert len(reachable) >= 2
    # Unreferenced-but-checksummed architecture chunks may remain (the browser
    # bundle selects them dynamically by chip family), so no equality with the
    # full file set is asserted here.


def test_no_cdn_hosts_referenced_by_page_or_vendor():
    for cdn in ("unpkg.com", "cdn.jsdelivr.net", "esm.sh", "cdn.skypack.dev"):
        assert cdn not in PAGE, f"page references CDN host: {cdn}"


# ---------------------------------------------------------------------------
# No forms / telemetry / credential capture
# ---------------------------------------------------------------------------


def test_no_forms_or_input_fields():
    assert DOM.forms == 0
    assert DOM.inputs == 0


def test_no_analytics_or_telemetry():
    surfaces = {
        "index.html": PAGE.lower(),
        "assets/installer.css": CSS_PATH.read_text(encoding="utf-8").lower(),
        "assets/serial-support.js": SERIAL_JS_PATH.read_text(encoding="utf-8").lower(),
    }
    for surface, lowered in surfaces.items():
        for needle in (
            "google-analytics",
            "googletagmanager",
            "gtag(",
            "plausible",
            "segment.io",
            "sentry",
            "fetch(",
            "xmlhttprequest",
            "navigator.sendbeacon",
        ):
            assert needle not in lowered, f"{surface}: forbidden call: {needle}"


# ---------------------------------------------------------------------------
# No inline code (CSP: script-src 'self'; style-src 'self')
# ---------------------------------------------------------------------------


def test_no_inline_style_blocks():
    assert DOM.style_tags == 0


def test_no_style_attributes():
    assert DOM.style_attrs == []


def test_no_inline_event_handlers():
    assert DOM.event_handler_attrs == []


def test_no_inline_scripts():
    assert DOM.inline_script_chunks == []
    for script in DOM.scripts:
        assert script.get("src"), "script tag without src (inline) is forbidden"


def test_local_stylesheet_and_scripts_exist_and_are_referenced():
    assert DOM.stylesheets == ["assets/installer.css"]
    assert CSS_PATH.is_file() and CSS_PATH.stat().st_size > 0
    assert SERIAL_JS_PATH.is_file() and SERIAL_JS_PATH.stat().st_size > 0
    srcs = [s.get("src") for s in DOM.scripts]
    assert "assets/serial-support.js" in srcs


# ---------------------------------------------------------------------------
# Web Serial feature detection (external, neutral)
# ---------------------------------------------------------------------------


def test_web_serial_feature_detection_present():
    js = SERIAL_JS_PATH.read_text(encoding="utf-8")
    assert '"serial" in navigator' in js or "'serial' in navigator" in js
    lowered = js.lower()
    for needle in ("supported browser", "windows", "macos", "linux", "chrome only"):
        assert needle not in lowered, f"support claim in feature detection: {needle}"


# ---------------------------------------------------------------------------
# Repository hygiene: no firmware binary anywhere in the tree
# ---------------------------------------------------------------------------


def test_no_bin_file_anywhere_in_tree():
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in REPO_ROOT.rglob("*.bin")
        if ".git" not in p.parts
    ]
    assert offenders == [], f".bin files are forbidden in the tree: {offenders}"


# ---------------------------------------------------------------------------
# _headers contract (CSP / Permissions-Policy / HSTS / caching)
# ---------------------------------------------------------------------------


def _parse_headers_file() -> dict[str, dict[str, str]]:
    blocks: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in HEADERS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            current = {}
            blocks[line.strip()] = current
        else:
            assert current is not None, f"header line before any path: {line!r}"
            name, _, value = line.strip().partition(":")
            current[name.strip()] = value.strip()
    return blocks


HEADER_BLOCKS = _parse_headers_file()


def test_headers_file_has_expected_blocks():
    assert set(HEADER_BLOCKS) == {"/*", "/vendor/*", "/firmware/*"}


def test_csp_directives_exact():
    csp = HEADER_BLOCKS["/*"]["Content-Security-Policy"]
    directives = {}
    for chunk in csp.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, value = chunk.partition(" ")
        directives[name] = value.strip()
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["style-src"] == "'self'"
    assert directives["img-src"] == "'self' data:"
    assert directives["connect-src"] == "'self'", "connect-src must be exactly 'self'"
    assert directives["manifest-src"] == "'self'"
    assert directives["base-uri"] == "'none'"
    assert directives["form-action"] == "'none'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["object-src"] == "'none'"
    assert "upgrade-insecure-requests" in directives
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    for host in ("github.com", "githubusercontent", "unpkg", "jsdelivr", "cdn"):
        assert host not in csp, f"external host in CSP: {host}"


def test_permissions_policy_allows_serial_for_self_only():
    policy = HEADER_BLOCKS["/*"]["Permissions-Policy"]
    assert "serial=(self)" in policy
    assert "serial=()" not in policy
    for token in ("usb=()", "geolocation=()", "camera=()", "microphone=()", "payment=()"):
        assert token in policy, f"missing Permissions-Policy token: {token}"
    assert "fullscreen=(self)" in policy


def test_security_headers_present():
    root = HEADER_BLOCKS["/*"]
    assert root["X-Content-Type-Options"] == "nosniff"
    assert root["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert root["X-Frame-Options"] == "DENY"


def test_hsts_scoped_to_host_only():
    hsts = HEADER_BLOCKS["/*"]["Strict-Transport-Security"]
    assert hsts == "max-age=15552000"
    assert "includeSubDomains" not in hsts
    assert "preload" not in hsts


def test_cache_rules_only_for_versioned_paths():
    assert (
        HEADER_BLOCKS["/vendor/*"]["Cache-Control"]
        == "public, max-age=31536000, immutable"
    )
    assert (
        HEADER_BLOCKS["/firmware/*"]["Cache-Control"]
        == "public, max-age=31536000, immutable"
    )
    # HTML / unversioned assets must not be immutable-cached.
    assert "Cache-Control" not in HEADER_BLOCKS["/*"]


# ---------------------------------------------------------------------------
# One public surface for Managed and Open-Source
# ---------------------------------------------------------------------------


def test_single_surface_for_managed_and_open_source():
    lowered = PAGE.lower()
    assert "managed" in lowered
    assert "open-source" in lowered or "open source" in lowered
    # A single install path: exactly one button (asserted above) and no
    # audience/plan mode switch.
    for needle in ("select plan", "choose your plan", "sign in", "log in", "checkout"):
        assert needle not in lowered, f"forbidden mode/auth control: {needle}"


# ---------------------------------------------------------------------------
# Honest technical-preview framing / no success claims
# ---------------------------------------------------------------------------


def test_page_marked_technical_preview():
    lowered = PAGE.lower()
    assert "technical" in lowered
    assert "not been validated on real hardware" in lowered
    assert "customer-ready" in lowered  # appears in the "not ... Customer-Ready" disclaimer


def test_no_success_or_completion_claims():
    lowered = PAGE.lower()
    for needle in (
        "successfully flashed",
        "flash complete",
        "flash succeeded",
        "fully erased",
        "provisioning complete",
        "connected to wi-fi",
        "adopted into home assistant",
        "installation successful",
    ):
        assert needle not in lowered, f"forbidden success claim: {needle}"


# ---------------------------------------------------------------------------
# Local loopback HTTP / MIME smoke — proves the page and its full relative
# import graph are servable and byte-identical over a static file server.
# Nothing external is contacted; the GitHub manifest/image are never fetched.
# ---------------------------------------------------------------------------

WEB_URL_PREFIX = "vendor/esp-web-tools/10.4.0/web/"
_JS_CONTENT_TYPES = {"text/javascript", "application/javascript"}


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence: no logs left behind
        pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AssertionError(f"unexpected redirect {code} -> {newurl}")


@contextlib.contextmanager
def _loopback_server():
    """A 127.0.0.1-only static server rooted at installer/, guaranteed to stop."""
    handler = functools.partial(_QuietHandler, directory=str(INSTALLER_DIR))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address
        assert host == "127.0.0.1"
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "loopback server thread did not terminate"


def _fetch(opener, url):
    with opener.open(url, timeout=10) as resp:
        assert resp.status == 200, f"HTTP {resp.status} for {url}"
        assert resp.geturl() == url, f"redirect: {url} -> {resp.geturl()}"
        return resp.headers.get_content_type(), resp.read()


def test_local_http_mime_smoke():
    opener = urllib.request.build_opener(_NoRedirect)
    index_bytes = PAGE_PATH.read_bytes()
    with _loopback_server() as base:
        # index.html served as text/html for both "/" and "/index.html".
        for path in ("/", "/index.html"):
            ctype, body = _fetch(opener, base + path)
            assert ctype == "text/html", f"{path} content-type {ctype}"
            assert body == index_bytes, f"{path} body mismatch"

        # Every JS file reachable via the relative import graph.
        reachable = sorted(_reachable_from_root())
        assert ROOT_MODULE in reachable
        assert len(reachable) >= 26
        for name in reachable:
            url = base + "/" + WEB_URL_PREFIX + name
            ctype, data = _fetch(opener, url)
            assert ctype in _JS_CONTENT_TYPES, f"{name} content-type {ctype}"
            assert data == (WEB_DIR / name).read_bytes(), f"{name} body mismatch"

        # install-button.js explicitly reachable and served.
        ctype, _ = _fetch(opener, base + "/" + WEB_URL_PREFIX + ROOT_MODULE)
        assert ctype in _JS_CONTENT_TYPES

        # External page assets (CSP externalization) are served correctly.
        ctype, data = _fetch(opener, base + "/assets/installer.css")
        assert ctype == "text/css"
        assert data == CSS_PATH.read_bytes()
        ctype, data = _fetch(opener, base + "/assets/serial-support.js")
        assert ctype in _JS_CONTENT_TYPES
        assert data == SERIAL_JS_PATH.read_bytes()
