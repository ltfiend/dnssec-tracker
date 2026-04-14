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
| Live DNS     | DNSKEY/SOA/CDS/CDNSKEY (with RRSIGs via DO=1) queried **directly at the zone's authoritative NS** every 60 s, DS queried **directly at the parent zone's authoritative NS** every 300 s. NS discovery rides through `local_resolver`; every observation is authoritative. First NS that answers cleanly wins; `SERVFAIL` / `REFUSED` / timeouts fall through to the next NS in the list. |
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
| `dns_probe` (zone)   | every 60 s  | **4 DNS queries** (`DNSKEY`, `SOA`, `CDS`, `CDNSKEY`) sent directly to one authoritative NS for the zone. RRSIGs over DNSKEY come back for free via DO=1 so there's no separate RRSIG query. | UDP/53 to an authoritative NS |
| `dns_probe` (parent) | every 300 s | **1 DNS query** (`DS`) sent directly to one authoritative NS for the *parent* zone (e.g. a TLD server for `net` when the child is `fus3d.net`). | UDP/53 to an authoritative NS |
| NS discovery         | every `parent_interval` per distinct zone or parent | **1 NS query** + 1 `A` lookup per returned NS name, via `local_resolver`. Result is cached in-process so the DNSKEY / SOA / DS passes don't re-discover. | UDP/53 to `local_resolver` |
| `rndc_status` | every 300 s     | **1 `rndc dnssec -status <zone>`** subprocess invocation to `rndc_server` (default `127.0.0.1:953`) | localhost TCP/953 |
| `state_file`  | every 30 s      | Filesystem scan (`rglob`) of `key_dir`; every `K*.state` file is stat'd and re-read | local FS read |
| `key_file`    | every 30 s      | Filesystem scan (`rglob`) of `key_dir`; every `K*.key` file is stat'd and re-read | local FS read |
| `syslog`      | continuous tail | `stat()` every 1 s, read only the delta since last offset | local FS read |
| `named_log`   | continuous tail | `stat()` every 1 s, read only the delta since last offset | local FS read |

Per one zone, at defaults, the outgoing traffic works out to:

| Channel                                   | Per minute | Per hour | Per day    |
| ----------------------------------------- | ---------: | -------: | ---------: |
| DNS queries → zone's auth NS              | 4          | 240      | **5,760**  |
| DNS queries → parent's auth NS (DS)       | 0.2        | 12       | 288        |
| NS-discovery queries → `local_resolver`   | ≈ 0.05 + 0.05·N_ns per distinct zone/parent per cache cycle | ≈ 1–4  | ≈ 24–96 |
| rndc calls → `rndc_server`                | 0.2        | 12       | **288**    |
| Filesystem scans of `key_dir` (`state_file` + `key_file`) | 4 | 240 | 5,760 |
| Syslog / named.log `stat()` calls         | 120 (2/s)  | 7,200    | 172,800    |

Concretely: **one zone generates roughly 6 k authoritative DNS
queries + a handful of recursor discovery queries + 288 rndc calls
per day**. Authoritative and rndc rates scale linearly with the
number of zones; NS-discovery queries scale with the number of
*distinct* zones and *distinct* parents, so adding a second zone
under the same TLD adds almost no discovery overhead.

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

### Authoritative queries

The tracker does not rely on any cache between itself and the real
source of truth. Every observation query goes directly to an
authoritative nameserver:

* **Zone-side queries** (DNSKEY / SOA / CDS / CDNSKEY, plus RRSIGs
  via DO=1) go to the zone's own authoritative NS set. That set is
  discovered by doing a single `NS` query for the zone against the
  configured `local_resolver`, then an `A` lookup for each NS
  hostname. The resulting `(ip, hostname)` list is cached in-process
  for `parent_interval` seconds so discovery runs at most once per
  cycle.
* **Parent-side DS queries** go to the *actual parent zone's*
  authoritative NS. The parent zone is derived by stripping the
  leading label (`fus3d.net` → `net`, `net` → `.`); its NS set is
  discovered the same way. So for `fus3d.net` the tracker literally
  asks one of the `{a,b,…}.gtld-servers.net` servers for
  `fus3d.net DS`, not whatever a caching recursor happens to
  remember.
* **"Any one good response is enough"**: for each query, the tracker
  walks the discovered NS list in order and stops at the first clean
  answer (`NOERROR` or `NXDOMAIN`). `SERVFAIL`, `REFUSED`, timeouts,
  and socket errors are treated as retryable and fall through to the
  next NS. Only when every NS in the list fails does the query come
  back empty and log a `WARNING: all authoritative NS failed for …`.

The `local_resolver` config key is therefore used purely as NS /
glue plumbing — it never sees a DNSKEY, DS, CDS, CDNSKEY, SOA, or
RRSIG query. If you want to test that path against a specific
recursor, point `local_resolver` at it; otherwise any recursor that
can reach root + the relevant TLDs will do.

### Query logging

Every active probe (`dns_probe`, `rndc_status`) emits a structured
`send` / `recv` log line at INFO level so you can see *exactly* what
the tracker is asking for and what came back. The fields are
consistent and grep-friendly. Here is a real sequence from a parent
DS probe where the first TLD server answered `SERVFAIL` and the
tracker fell through to the second:

```
dnssec_tracker.query.dns INFO    discover: zone=net (resolving NS+A via recursor 127.0.0.1:53)
dnssec_tracker.query.dns INFO    discover: zone=net ns_count=2 ips=['192.5.6.30', '192.33.14.30']
dnssec_tracker.query.dns INFO    send: server=192.5.6.30:53 ns=a.gtld-servers.net protocol=UDP role=parent name=fus3d.net type=DS timeout=5.0s
dnssec_tracker.query.dns WARNING recv: server=192.5.6.30:53 ns=a.gtld-servers.net protocol=UDP role=parent name=fus3d.net type=DS rcode=SERVFAIL RETRY_NEXT_NS elapsed_ms=4.1
dnssec_tracker.query.dns INFO    send: server=192.33.14.30:53 ns=b.gtld-servers.net protocol=UDP role=parent name=fus3d.net type=DS timeout=5.0s
dnssec_tracker.query.dns INFO    recv: server=192.33.14.30:53 ns=b.gtld-servers.net protocol=UDP role=parent name=fus3d.net type=DS rcode=NOERROR answers=1 elapsed_ms=12.8
```

And a typical `rndc_status` pair:

```
dnssec_tracker.query.rndc INFO  send: server=127.0.0.1:953 zone=example.com cmd=/usr/sbin/rndc -k /mnt/bind/rndc.key -s 127.0.0.1 -p 953 dnssec -status example.com
dnssec_tracker.query.rndc INFO  recv: server=127.0.0.1:953 zone=example.com rc=0 stdout_bytes=890 stderr_bytes=0 elapsed_ms=44.7
```

Fields for the DNS `discover` line:

| Field | Meaning |
| --- | --- |
| `zone` | The zone whose NS set is being resolved (for parent probes this will be the *parent* zone, e.g. `net`) |
| `ns_count`, `ips` | Number and IP addresses of the authoritative NS that will be queried in order |

Fields for the DNS `send` line:

| Field | Meaning |
| --- | --- |
| `server` | IP and port of the authoritative NS that the query is being sent to |
| `ns` | Hostname of that NS (e.g. `a.gtld-servers.net`) so you don't have to reverse-resolve IPs from the log |
| `protocol` | `UDP` nominally; upgrades to `UDP+TCP` on the `recv` line if the response had the `TC` bit set and a TCP retry happened |
| `role` | `zone` for DNSKEY / SOA / CDS / CDNSKEY, `parent` for DS |
| `name`, `type` | Qname and qtype |
| `timeout` | Per-query timeout from `dns.query_timeout` |

Fields added on the DNS `recv` line: `rcode` (`NOERROR`, `NXDOMAIN`,
`SERVFAIL`, `REFUSED`, …), `answers` (rrset record count), and
`elapsed_ms`. Retryable failures — `SERVFAIL`, `REFUSED`, timeouts,
and socket errors — are logged at WARNING with either the rcode and
`RETRY_NEXT_NS` marker or the exception class and message, so a
filter like `grep WARNING` shows only the unhealthy queries. When
every NS in the discovered list fails, a summary line reports
`all authoritative NS failed for <name> <type> role=<role>`.

The individual answer records are logged at DEBUG under the same
loggers, so `--log-level DEBUG` dumps the full wire-form rdata
alongside the summary line without flooding normal operation. To
focus on one channel:

```bash
# only DNS queries, not rndc
docker logs -f dnssec-tracker 2>&1 | grep dnssec_tracker.query.dns

# only failures across both channels
docker logs -f dnssec-tracker 2>&1 | grep 'query\.\(dns\|rndc\).*WARNING'
```

Running the container with `--log-level DEBUG` enables the answer
dumps:

```yaml
# docker-compose.example.yml
    command: ["python", "-m", "dnssec_tracker",
              "--config", "/etc/dnssec-tracker/dnssec-tracker.conf",
              "--log-level", "DEBUG"]
```

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

### Forcing an immediate refresh

The tracker normally polls on the intervals documented in
[Traffic and load per zone](#traffic-and-load-per-zone). If you've just
made a change and don't want to wait for the next tick, force every
collector to run a sample pass right now:

```bash
docker exec dnssec-tracker dnssec-tracker --refresh
```

(or equivalently `docker compose exec dnssec-tracker dnssec-tracker --refresh`).

This hits `POST /api/refresh` on the running instance inside the
container and prints a per-collector timing summary, for example:

```
Forced refresh on http://127.0.0.1:8080/api/refresh:
  state_file   ok   (4.2 ms)
  key_file     ok   (3.1 ms)
  syslog       ok   (0.0 ms)
  named_log    ok   (0.0 ms)
  dns_probe    ok   (62.4 ms)
  rndc_status  ok   (118.7 ms)
```

Forced and scheduled samples share a per-collector lock so an
out-of-band refresh never races a polling pass in-flight. For
`dns_probe`, forcing runs **both** the zone probe and the parent DS
probe — the usual 5-minute parent-interval gate is bypassed so you see
the current parent state immediately. The streaming collectors
(`syslog`, `named_log`) report `ok` in zero time because they already
tail their files with one-second granularity.

`POST /api/refresh` is unauthenticated, like the rest of the web UI —
treat the tracker as a trusted-network tool and expose it via SSH
tunnel or a reverse proxy in production.

### Cleaning up deleted keys

When you delete a key from BIND's key directory — whether you're
retiring a rollover experiment, pruning a `.bak` tree, or an iodyn
retirement pass has moved a key out of scope — the tracker still
holds that key's snapshots, `keys`-table row, and rollover-chart
presence. The event log is an append-only historical record and
stays intact; but forward-looking views (rollover, per-key page,
key inventory) keep listing the key until you explicitly tell the
tracker the file is gone.

Cleanup is a **manual** action. The polling collectors never run
it on their own — a momentary file disappearance during a BIND
reload or an iodyn `dnssec-settime` race shouldn't wipe a key's
data as a 30-second-poll side effect. When you're ready:

```bash
docker exec dnssec-tracker dnssec-tracker --clean-deleted-keys
```

Or `POST /api/clean-deleted-keys` directly from a trusted-network
caller. Sample output:

```
Clean deleted keys on http://127.0.0.1:8080/api/clean-deleted-keys:
  scopes on disk now:    4
  scopes previously seen: 6
  cleaned: 2 key(s):
    - example.com KSK tag=12345 (last seen at /etc/bind/keys/example.com/Kexample.com.+013+12345.state)
    - test.invalid ZSK tag=67890 (last seen at /etc/bind/keys/test.invalid/Ktest.invalid.+013+67890.state)
```

What the cleanup does for each vanished key:

* Emits **one** `state_key_file_deleted` event with
  `detail.last_fields` (the final state the collector observed),
  `detail.last_path`, and `detail.trigger="manual"` — a single
  summary, not a flood of per-field `(unset)` transitions.
* Drops the `state_file` and `key_file` collector snapshots so
  the rollover / per-key views stop rendering the key.
* Removes the row from the `keys` table.

Historical events are **not touched** — they carry their own
zone / tag / role metadata and continue to render in the event log
and on the timelines.

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
