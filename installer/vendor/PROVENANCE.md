# Vendored runtime provenance

This directory contains **self-hosted, third-party runtime assets** for the
PVAutonomy browser installer page (`installer/index.html`). Nothing here is
authored by PVAutonomy; the assets are pinned copies of an official upstream
release, checked in verbatim so the page loads **no** CDN, `unpkg`, `jsDelivr`,
or other remote script source at runtime (ADR-0004 §6, §21).

## esp-web-tools

| Field | Value |
|---|---|
| Package | `esp-web-tools` (npm) |
| Version (pinned) | **10.4.0** |
| Upstream project | ESPHome — <https://github.com/esphome/esp-web-tools> |
| Source (immutable) | npm registry tarball `esp-web-tools-10.4.0.tgz` |
| Source URL | <https://registry.npmjs.org/esp-web-tools/-/esp-web-tools-10.4.0.tgz> |
| Tarball SHA-256 | `f18da75335d2f0dca044c4bb052848c0696e7b03cc23d61d8530dd6eba0a9008` |
| Tarball SHA-1 (registry `dist.shasum`) | `594e2c7c06dced84bfc6dd1d0ee80e591867769f` |
| License | Apache-2.0 (see `esp-web-tools/10.4.0/LICENSE`) |
| Vendored subtree | the browser bundle `dist/web/` (26 `*.js` files) + `LICENSE` |
| Location | `esp-web-tools/10.4.0/web/` |

### Why `dist/web/` and not `dist/`

The tarball ships two builds. The top-level `dist/*.js` (`package.json`
`main`) uses **bare** ES-module specifiers (`lit`, `@material/web/…`,
`esptool-js`, `improv-wifi-serial-sdk`, `tslib`) that a browser cannot resolve
without a bundler or import map — it is **not** self-hostable as-is.

The `dist/web/` build is the pre-bundled browser artifact: every import inside
it is **relative** (`import("./install-dialog-<hash>.js")`), all lazily-loaded
chunks are present in the same directory, and it references **no** remote
runtime dependency. It is therefore complete and self-contained. This is the
entry the upstream project itself serves for browser/serial installs. The
custom element is defined in `web/install-button.js`
(`customElements.define("esp-web-install-button", …)`).

The only absolute URLs inside the bundle are XML namespace URIs
(`w3.org`), an upstream documentation link, a Home Assistant redirect link, and
neutral USB-to-UART driver pages (Silabs / WCH) — none are runtime script
sources.

### Integrity

`esp-web-tools/10.4.0/SHA256SUMS` lists the SHA-256 of every vendored file
(paths relative to `esp-web-tools/10.4.0/`). Verify with:

```
cd installer/vendor/esp-web-tools/10.4.0 && shasum -a 256 -c SHA256SUMS
```

### Updating

Bump by adding a **new** pinned version directory
(`esp-web-tools/<new-version>/…`) with its own `SHA256SUMS`, re-deriving the
tarball hash from the official registry, and repointing the page's
`<script type="module">`. Do not mutate a pinned version tree in place.
