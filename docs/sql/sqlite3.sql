-- Schema for output_plugins/sqlite.py. Applied automatically on first run against a fresh db_file;
-- can also be applied manually: sqlite3 <db_file> < docs/sql/sqlite3.sql
--
-- Denormalised (one row per event), unlike docs/sql/mysql.sql's lookup-table design: this is a local-lab
-- output, not a fleet-wide store, so simple querying matters more than storage/dedup. Columns cover the
-- event schema fields shared by every route (see CLAUDE.md); route-specific extras (waf_signature,
-- ns_txn_id, leaked_fake, ioc_source, nitro_user, nitro_pass, rand_key, matched, headers, body_sha256,
-- body_b64, ...) are kept losslessly in `extra` as a JSON blob instead of growing the schema per CVE.

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT,
  unixtime REAL,
  eventid TEXT,
  src_ip TEXT,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  sensor TEXT,
  request TEXT,
  url TEXT,
  message TEXT,
  cve TEXT,
  route_id TEXT,
  patched INTEGER,
  profile TEXT,
  body TEXT,
  payload TEXT,
  extra TEXT
);

CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events (timestamp);
CREATE INDEX IF NOT EXISTS events_src_ip_idx ON events (src_ip);
CREATE INDEX IF NOT EXISTS events_cve_idx ON events (cve);
