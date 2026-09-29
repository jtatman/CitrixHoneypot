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

### Added

* Appliance profiles (`profiles/*.yaml`, `--profile`): product/build, headers, cookies, login page, TLS CN, per-CVE vulnerable/patched/off
* CVE state derived from the profile's `build` using a vendored fix-version table (`core/data/cves.json`, from citrixscan)
* Automatic self-signed certificate generation; `patched` and `profile` fields on events; HTTP status codes on responses

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
