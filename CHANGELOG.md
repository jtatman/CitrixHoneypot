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

### Added

* Appliance profiles (`profiles/*.yaml`, `--profile`): product/build, headers, cookies, login page, TLS CN, per-CVE vulnerable/patched/off
* CVE state derived from the profile's `build` using a vendored fix-version table (`core/data/cves.json`, from citrixscan)
* Automatic self-signed certificate generation; `patched` and `profile` fields on events; HTTP status codes on responses

* Profile options `features`, `not_found`, `mangle_connection`, `epa_deb_size`, `rdx_en_mtime`; modern profiles `adc-14.1-73.33-vulnerable` and `adc-14.1-73.37-patched`
* NetScaler surface (`netscaler-surface`): Citrix logon page markers, `Cneonction` header, `nsepa.deb` size patch oracle for CTX697096 with Range support, `rdx_en.json.gz` gzip-MTIME fingerprint
* Routes for CVE-2025-5777 (CitrixBleed 2, fake canned leak) and CVE-2023-3519; CTX697096 (CVE-2026-88771..88778) added to the CVE table
* Memory-overread detection oracles: CVE-2023-4966 (CitrixBleed), CVE-2023-6549, CVE-2026-3055 (all canned/random fake data, never real memory)
* CVE-2020-8193/8195/8196 unauthenticated-endpoint + LFI detection oracle (fake /etc/passwd, fixed versions verified against NVD)

### Changed

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
