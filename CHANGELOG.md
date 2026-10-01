# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

* POST and HEAD requests were never dispatched (`render` always called `render_GET`); POST exploit payloads are now logged as `citrix.payload`
* POST without a `title` field or with a non-UTF-8 body no longer crashes the handler
* All `Set-Cookie` headers are now sent (previously only the last survived); `Content-Length` counts bytes
* Struggle check now actually returns the gold star page
* Control characters in logged request paths are escaped
* Replaced deprecated `datetime.utcfromtimestamp`
* `dispatch()`'s default "patched" fallback no longer leaks a route's `data`/`cookies`/`headers` into the not-found response it's supposed to replace
* `GET /` (and `/vpn/`, etc.) with a query string no longer 404s -- `Ctx` used to split the raw path into segments without stripping the query string first, breaking on any request with query params (found via nmap's `http-waf-detect`)
* `output_plugins/sqlite.py` was an empty stub; now a working output plugin

### Added

* Appliance profiles (`profiles/*.yaml`, `--profile`): product/build, headers, cookies, login page, TLS CN, per-CVE vulnerable/patched/off
* CVE state derived from the profile's `build` using a vendored fix-version table (`core/data/cves.json`, from citrixscan)
* Automatic self-signed certificate generation; `patched` and `profile` fields on events; HTTP status codes on responses

* Profile options `features`, `not_found`, `mangle_connection`, `epa_deb_size`, `rdx_en_mtime`; modern profiles `adc-14.1-73.33-vulnerable` and `adc-14.1-73.37-patched`
* NetScaler surface (`netscaler-surface`): Citrix logon page markers, `Cneonction` header, `nsepa.deb` size patch oracle for CTX697096 with Range support, `rdx_en.json.gz` gzip-MTIME fingerprint
* Routes for CVE-2025-5777 (CitrixBleed 2, fake canned leak) and CVE-2023-3519; CTX697096 (CVE-2026-88771..88778) added to the CVE table
* Memory-overread detection oracles: CVE-2023-4966 (CitrixBleed), CVE-2023-6549, CVE-2026-3055 (all canned/random fake data, never real memory)
* CVE-2020-8193/8195/8196 unauthenticated-endpoint + LFI detection oracle (fake /etc/passwd, fixed versions verified against NVD)
* CVE-2026-88771 attempt/IOC fingerprinting (login command-injection attempt, webshell check-in probe), from GreyNoise's published IOCs
* Generic, CVE-agnostic IOC/misconfig-path logging (`core/routes/ioc_probes.py`), vendored from citrixscan's IOC_PATHS/MISCONFIG_PATHS
* CVE-2026-8452 IOC (webshell path `/vpn/theme/x.php`) and CVE-2026-88771/88772 log-poisoning payload signature detection, from a
  GitHub survey of watchTowr Labs' detection tooling
* `X-NITRO-USER`/`X-NITRO-PASS`/`rand_key` header telemetry and a corrected HTTP 406 status for the CVE-2020-8193 family's detection oracle
* Opt-in AppFirewall/WAF-mimicry layer (`core/routes/waf_block.py`, `waf-mimicry` profile feature, new `adc-14.1-73.33-waf` profile):
  generic SQLi/XSS/command-injection/traversal signatures get a plausible 403 + `NS Transaction ID` block instead of silent 200/404,
  without shadowing any specific CVE/IOC route. Live-tested against katana (unaffected) and vigolium's known-issue-scan (the predicted
  scanner back-off did not occur; see docs/SCANNER_SURFACE.md)
* SQLite output plugin (`output_plugins/sqlite.py`, `[output_sqlite]`): schema (`docs/sql/sqlite3.sql`) auto-applied on first run;
  one row per event with the common fields as columns and route-specific extras (`waf_signature`, `ioc_source`, `nitro_user`, ...)
  losslessly in a JSON `extra` column
* `output_jsonlog`'s `logfile` option accepts `-`/`stdout` to write JSONL to stdout instead of a rotated file
* Elasticsearch/OpenSearch output plugin (`output_plugins/elasticsearch.py`, `[output_elasticsearch]`): stdlib `urllib`,
  no extra dependency; POSTs each event as a document to `{scheme}://{host}:{port}/{index}/_doc`
* Syslog output plugin (`output_plugins/syslog.py`, `[output_syslog]`): stdlib `socket`; sends each event to a remote
  syslog server, RFC 3164-framed, body as CEF (default) or JSON, over UDP or TCP
* Optional plain-HTTP listener: `[honeypot] http_port` / `--http-port` (0 = disabled) binds a second, TLS-less
  listener on the same site/routes, for local-lab convenience (tools that don't handle a self-signed cert well)
* Multiple TLS ports: `[honeypot] extra_listen_ports` / `--ports` binds the same site/cert/profile to additional
  ports alongside `-p`/`port` (e.g. "8443,3010")
* `--tls-profile` / `[honeypot] tls_profile`: take the TLS cert subject CN from a different appliance profile
  than `--profile`, for testing cert-based fingerprinting independently of the HTTP surface
* Localhost-only health endpoint: `core/health.py`, `[honeypot] health_port` / `--health-port` (0 = disabled).
  Bound to 127.0.0.1 regardless of `-a`/`--addr`; not part of the emulated surface, never logged as an event
* `docker-compose.yml`: a network-isolated local lab. Uses a custom bridge network with
  `com.docker.network.bridge.enable_ip_masquerade: "false"` rather than `internal: true` (which would also
  block the published ports a honeypot needs for inbound traffic) to block the container's own outbound
  internet access

### Changed

* `output_plugins/mysql.py`'s `geoip` option now defaults to `false` (was `true`); `geoip2` is imported lazily, only
  when geoip is enabled, so the plugin no longer requires `geoip2`/`maxminddb` unless geolocation is opted into.
  Those two packages moved from `requirements-mysql.txt` to a new `requirements-geoip.txt`
* Request handling refactored into a route table (`core/routes/`); events gain `cve` and `route_id` fields
* Python 3.10+ required; dependencies modernised, MySQL/GeoIP moved to `requirements-mysql.txt`
* Docker image: pinned `python:3.12-slim`, non-root, listens on 8443
* Added pytest suite and GitHub Actions CI

## [2.0.2]

### Changed in version 2.0.2

* Now handling custom HTTP requests, not just HEAD, GET, and POST
* Fixed an error in the MySQL plugin error handler
* Improved the `Dockerfile`
* Minor optimizations

## [2.0.1]

### Changed in version 2.0.1

* Fixed a bug when responding to certain requests

## [2.0.0]

### Added in version 2.0.0

* A script for starting, stopping, and restarting the honeypot
* Config file support
* Various command-line options
* HEAD requests are now logged too
* Output plugin support
* Output plugin for JSON
* Output plugin for MySQL
* Log rotation

### Changed in version 2.0.0

* Made the script compatible with Python 2.7
* The HTTPS server and the logging now use the Twisted framework
* Rewrote the documentation
