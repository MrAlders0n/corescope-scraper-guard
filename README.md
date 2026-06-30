# corescope-scraper-guard

A single-file, dependency-free Python tool that **detects scrapers** hitting a
[CoreScope](https://github.com/) instance (or any Caddy-fronted service) and, once
an IP has *persistently* behaved like a scraper for hours, **auto-bans it at the
firewall** — with a dry-run mode, allowlist, TTL-based expiry, and an audit log.

It reads the Caddy access log straight out of `docker logs`, so there's nothing to
install on the box beyond Python 3.

## Why

A public live-data feed (mesh nodes, packets, observers) gets scraped by
aggregators and bots. CORS/Origin checks don't stop server-side scrapers, and
banning IPs by hand is whack-a-mole. This tool fingerprints the behaviour, builds
confidence over many hours (so it doesn't ban real users on a hunch), and then
drops the firewall on the ones that keep at it.

## How it detects scrapers

Each run classifies every client IP from the access log. The fingerprints are
things a real browser never does:

| Verdict | Signature | Auto-ban? |
|---|---|---|
| `WS-SCRAPER` | Pure WebSocket feed puller (opens `/ws`, never loads the page or polls the API), **or** sends a forged duplicate `Origin` header | ✅ (unambiguous) |
| `BOT-UA` | Non-browser User-Agent (`python-requests`, `curl`, `Go-http-client`, `scrapy`, `aiohttp`, `httpx`, `wget`, …) | ✅ (unambiguous) |
| `REST-HARVESTER` | Zero page loads, zero WS, but repeatedly pulls the bulk dataset (node list / observers / region config / clock-skew) | ⚠️ only with `--ban-harvesters` |

Real users (browsers that load assets, or just poll a stats endpoint) are **not**
flagged.

## How it decides to ban (confidence by persistence)

A single run only sees a short log window (and busy logs rotate), so the tool
**accumulates evidence across runs** in a state file. An IP becomes ban-eligible
only when it has looked like a scraper:

- for **≥ `--persist-hours`** (default **6h**),
- across **≥ `--min-runs`** runs (default **4**), and
- is **still active** (flagged within `--grace-hours`, default 2h).

By default only the *unambiguous* verdicts (`WS-SCRAPER`, `BOT-UA`) are ban-eligible.
Pass `--ban-harvesters` to also ban `REST-HARVESTER`s (they're often residential /
dynamic IPs — more collateral risk, so it's opt-in).

Bans are applied as `iptables` `DROP` rules in the `DOCKER-USER` chain (silent, no
retry-storm), recorded with a **14-day TTL** (`--ban-ttl-days`) so a reassigned
dynamic IP frees itself, **re-asserted every run** (survives reboots / docker
restarts), and capped at `--max-bans-per-run` (default 5) as a runaway guard.

## Requirements

- A host running the target service in **Docker**, fronted by **Caddy** with the
  access log in **console format on stderr** (so `docker logs <container>` contains
  JSON `handled request` lines). Example Caddyfile snippet:
  ```
  log {
      output stderr
      format console
      level INFO
  }
  ```
- **Python 3** (standard library only — no pip installs).
- For `--enforce`: passwordless `sudo iptables` and the `DOCKER-USER` chain (present
  whenever Docker is running). Dry-run needs no sudo.

## Usage

```bash
# Detect only (dry-run): show who WOULD be banned, touch nothing
python3 detect-scrapers.py --since 24h

# Enforce, including REST dataset-harvesters
python3 detect-scrapers.py --since 2h --ban-harvesters --enforce

# Management
python3 detect-scrapers.py --list-bans
python3 detect-scrapers.py --unban 1.2.3.4 --enforce
python3 detect-scrapers.py --ban   1.2.3.4 --enforce   # manual ban
```

Run it from cron. Start in **dry-run** to watch its judgement, then add `--enforce`
once you trust it:

```cron
# hourly, dry-run first:
17 * * * * /usr/bin/python3 $HOME/detect-scrapers.py --since 2h >> $HOME/scraper-scans.log 2>&1
# when ready, enforce (and include harvesters):
17 * * * * /usr/bin/python3 $HOME/detect-scrapers.py --since 2h --ban-harvesters --enforce >> $HOME/scraper-scans.log 2>&1
```

## Allowlist (false-positive escape hatch)

Real users occasionally trip the heuristic — e.g. a dashboard tab **left open for
days** has cached assets and a dropped WS, so its periodic API polling can look like
a `REST-HARVESTER`. Allowlist them:

```bash
echo '1.2.3.4   # why this is a real user' >> ~/.scraper-allowlist
```

Allowlisted IPs are never flagged, tracked, or banned — and **any existing ban for
them is auto-lifted on the next run**. (Also accepts `--allowlist 1.2.3.4,5.6.7.8`.)

## Files it writes (keep these out of git — see `.gitignore`)

| File | Purpose |
|---|---|
| `~/.scraper-state.json` | Per-IP evidence accumulation + active bans |
| `~/.scraper-allowlist` | Your allowlist (one IP per line, `#` comments) |
| `~/scraper-bans.log` | Append-only audit trail of every BAN / UNBAN / EXPIRE |
| `~/scraper-scans.log` | Cron scan output (if you redirect to it) |

## Options

```
--container       container name to read logs from (default: corescope)
--since           docker logs window, e.g. 24h / 6h (default: 24h)
--ban-harvesters  also ban REST dataset-harvesters (opt-in; residential risk)
--enforce         actually apply/expire firewall bans (default: dry-run)
--persist-hours   hours of persistent scraping before ban-eligible (default: 6)
--min-runs        minimum flagged runs before ban-eligible (default: 4)
--grace-hours     forget an IP if not re-flagged within this (default: 2)
--ban-ttl-days    auto-expire bans after N days (default: 14)
--max-bans-per-run runaway guard (default: 5)
--allowlist       comma-separated IPs to never ban
--allowlist-file  allowlist file (default: ~/.scraper-allowlist)
--state / --audit override state / audit-log paths
--no-rdns         skip reverse-DNS lookups
--list-bans / --unban <ip> / --ban <ip>   management commands
--json            machine-readable output
```

## Caveats

- It governs **IP bans only**; pair it with a non-browser-UA block at the proxy for
  belt-and-suspenders.
- Heuristics key off CoreScope's endpoints (`/api/nodes`, `/api/observers`, …) and
  the Caddy console-log format; adapt `verdict()` for other apps.
- The data being protected is usually public-by-design, so this raises the cost of
  scraping rather than making it impossible.

## License

MIT — see [LICENSE](LICENSE).
