# dnssec-tracker

Long-running passive observer of BIND 9.18 / 9.20 `dnssec-policy` events.

DNSSEC scenarios only reveal themselves over hours or days. `K*.state` files
overwrite in place, syslog ages out, and DNS queries only show the current
moment. `dnssec-tracker` runs alongside BIND, continuously samples every
observable signal, and persists a timestamped event stream you can browse in a
web UI and export as a polished HTML or PDF test report.

It is purely an **observer** — it never runs `rndc`, `dnssec-*`, or modifies
BIND configuration. Pair it with whatever tool is actually managing keys
(for example, [iodyn-dnssec](https://example.invalid/iodyn-dnssec)).

## What it watches

| Source       | How                                               |
| ------------ | ------------------------------------------------- |
| Key directory `K*.state` files | Polled every 30 s. The configured `key_dir` is walked **recursively** (`Path.rglob`) so the usual BIND layout of `<key_dir>/<zonename>/K*.state` is picked up, as are flat and deeper-nested layouts. |
| Key directory `K*.key` files   | Polled every 30 s, also recursively; timing comments parsed |
| syslog       | Tailed; iodyn-dnssec and named lines parsed       |
| named.log    | Tailed; `dnssec` category lines parsed            |
| Live DNS     | DNSKEY/RRSIG/CDS/CDNSKEY queried at the zone every 60 s, DS queried at the parent every 300 s |
| rndc (optional) | `rndc dnssec -status <zone>` every 5 min        |

All events land in a single SQLite database (`events.db`).

## Traffic and load per zone

The tracker is deliberately noisy at the "observe" end and completely
silent at the "act" end — nothing ever talks to the outside world
beyond read-only DNS queries. The default polling cadences are chosen
to be small enough that you can run the tracker against a production
nameserver without anybody noticing, but large enough that state
transitions on BIND's scale of minutes-to-hours aren't missed.

### Exact per-zone rates at the shipped defaults

| Collector     | Frequency       | Work done per pass per zone | Channel |
| ------------- | --------------- | --------------------------- | ------- |
| `dns_probe` (zone)   | every 60 s  | **5 DNS queries** (`DNSKEY`, `SOA`, `CDS`, `CDNSKEY`, `RRSIG`) to `local_resolver`  | UDP/53 |
| `dns_probe` (parent) | every 300 s | **1 DNS query** (`DS`) — uses `local_resolver` as a recursor so it reaches the actual parent through normal recursion | UDP/53 |
| `rndc_status` | every 300 s     | **1 `rndc dnssec -status <zone>`** subprocess invocation to `rndc_server` (default `127.0.0.1:953`) | localhost TCP/953 |
| `state_file`  | every 30 s      | Filesystem scan (`rglob`) of `key_dir`; every `K*.state` file is stat'd and re-read | local FS read |
| `key_file`    | every 30 s      | Filesystem scan (`rglob`) of `key_dir`; every `K*.key` file is stat'd and re-read | local FS read |
| `syslog`      | continuous tail | `stat()` every 1 s, read only the delta since last offset | local FS read |
| `named_log`   | continuous tail | `stat()` every 1 s, read only the delta since last offset | local FS read |

Per one zone, at defaults, the outgoing traffic works out to:

| Channel                       | Per minute | Per hour | Per day    |
| ----------------------------- | ---------: | -------: | ---------: |
| DNS queries → `local_resolver`| 5.2        | 312      | **7,488**  |
| &nbsp;&nbsp;of which to parent (DS) | 0.2  | 12       | 288        |
| rndc calls → `rndc_server`    | 0.2        | 12       | **288**    |
| Filesystem scans of `key_dir` (`state_file` + `key_file`) | 4 | 240 | 5,760 |
| Syslog / named.log `stat()` calls | 120 (2/s) | 7,200 | 172,800 |

Concretely: **one zone generates roughly 7.5 k DNS queries and 288
rndc calls per day**. Both rates scale linearly with the number of
zones the tracker discovers — 10 zones is ~75 k DNS queries + ~2,880
rndc calls per day, 100 zones is ~750 k DNS queries + ~28,800 rndc
calls per day.

### Bandwidth estimate per zone

For a typical dnssec-policy zone (1 KSK + 1 ZSK, ECDSA P-256):

| Direction | Per query (typical) | Per zone / hour | Per zone / day |
| --------- | -------------------:| ---------------:| --------------:|
| Outbound DNS (all types) | ~80 bytes  | ~25 KB   | ~600 KB  |
| Inbound DNS (DNSKEY+RRSIG dominate) | 150–2,000 bytes | ~120 KB | ~2.9 MB |
| rndc (localhost) | ~1.5 KB response | ~18 KB | ~430 KB |

Filesystem read volume from the `state_file` / `key_file` scans is
dominated by the number of keys present, not the poll cadence —
sqlite `WAL` keeps the database write volume to tens of KB per day
even on a busy rollover.

### What is **not** counted above

- **Web UI + JSON API**: zero traffic unless you actually load a page
  or hit an endpoint. The pages are served directly out of SQLite and
  the embedded Jinja templates, no background requests.
- **SQLite writes**: local-only, no network.
- **Report exports**: generated on demand; WeasyPrint runs entirely
  in-process.
- **DNS answers that didn't change**: a `state_file` or `dns_probe`
  pass that sees the same snapshot as last time produces zero event
  rows and zero writes to `events.db`.

### Dialling it down

Every knob above is in `config/dnssec-tracker.conf.example` under its
matching section. If you want a lighter touch — for example, on a zone
with extremely long DNSSEC intervals where minute-resolution is
overkill — the obvious levers are:

| Setting                         | Default | Effect when doubled |
| ------------------------------- | -------:| ------------------- |
| `dns.query_interval`            | 60 s    | halves DNS traffic to `local_resolver` |
| `dns.parent_interval`           | 300 s   | halves DS queries |
| `rndc.interval`                 | 300 s   | halves rndc calls |
| `collectors.state_file` = `off` | on      | removes one filesystem scan every 30 s |
| `collectors.key_file`  = `off`  | on      | removes one filesystem scan every 30 s |
| `collectors.dns_probe` = `off`  | on      | removes all DNS queries (state is still captured via `state_file` + `rndc_status`) |
| `collectors.rndc_status` = `off`| on      | removes all rndc calls (key state still captured via the on-disk `.state` files) |

If you need to record at a faster cadence during a tight rollover
window, dropping `dns.query_interval` to 15 s is still well under
BIND's own signing interval and has been tested to produce a
consistent event stream without drop-outs.

## Running

```bash
# Build
docker build -t dnssec-tracker .

# Run (see docker-compose.example.yml for the mount pattern)
docker compose -f docker-compose.example.yml up
```

Then open <http://localhost:8080/>.

### Mounts

The container expects these read-only mounts:

- `/mnt/bind/keys` — BIND's `key-directory` root
- `/mnt/host/var/log/syslog` — host syslog file
- `/mnt/bind/log/named.log` — BIND's log file (optional)

Plus one writable volume for the event database:

- `/var/lib/dnssec-tracker`

## Reports

Per-zone report endpoints:

- `GET /zones/{zone}/report.html?from=YYYY-MM-DD&to=YYYY-MM-DD` — standalone
  HTML with all data, CSS, and SVG inlined.
- `GET /zones/{zone}/report.pdf?from=YYYY-MM-DD&to=YYYY-MM-DD` — the same
  template rendered via WeasyPrint.

Both exports share one Jinja template so they stay in sync.

## Configuration

See `config/dnssec-tracker.conf.example`. The format mirrors iodyn-dnssec's
INI style so the two tools feel familiar side by side.

## Development

```bash
pip install -e '.[dev]'
pytest
python -m dnssec_tracker --config config/dnssec-tracker.conf.example
```
