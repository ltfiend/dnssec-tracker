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
| Key directory `K*.state` files | Polled every 30 s; every field change emitted as an event |
| Key directory `K*.key` files   | Polled every 30 s; timing comments parsed          |
| syslog       | Tailed; iodyn-dnssec and named lines parsed       |
| named.log    | Tailed; `dnssec` category lines parsed            |
| Live DNS     | DNSKEY/RRSIG/CDS/CDNSKEY queried at the zone every 60 s, DS queried at the parent every 300 s |
| rndc (optional) | `rndc dnssec -status <zone>` every 5 min        |

All events land in a single SQLite database (`events.db`).

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
