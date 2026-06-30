#!/usr/bin/env python3
"""
detect-scrapers.py — scraper detector + persistence-based auto-ban for
live.meshcore.ca (CoreScope).

Each run reads the Caddy access log from `docker logs corescope`, flags clients
that pull the feed like a bot (not a browser), and ACCUMULATES evidence across
runs in a state file. An IP that keeps looking like a high-confidence scraper
for a sustained period becomes ban-eligible. Because evidence is accumulated
across many short runs, this works even though log rotation means any single
run only sees a small window.

Fingerprints (things a real browser never does):
  * pure WebSocket-only    : opens /ws, never loads the page or polls /api/stats
  * forged duplicate Origin: sends the Origin header twice  (scripted client)
  * non-browser User-Agent : python-requests / curl / Go-http-client / ...
  * REST dataset-harvester : 0 page loads, 0 WS, repeatedly pulls node list /
                             observers / region config / clock-skew

Auto-ban policy (defaults; all tunable):
  * Only UNAMBIGUOUS verdicts (WS-SCRAPER, BOT-UA) are ban-eligible.
    REST-HARVESTER is reported but NEVER auto-banned (dynamic/residential IPs
    carry real collateral risk) — it stays recommend-only.
  * An IP must look like a scraper for >= PERSIST_HOURS, across >= MIN_RUNS
    runs, and still be active (flagged within GRACE_HOURS) to be eligible.
  * DRY-RUN by default: prints "WOULD BAN" and touches nothing. Pass --enforce
    to actually apply firewall DROP rules (iptables DOCKER-USER chain).
  * Bans auto-expire after BAN_TTL_DAYS (so a reassigned dynamic IP frees up).
  * Allowlist, per-run ban cap, and an audit log guard against mistakes.

Usage:
    python3 detect-scrapers.py                      # scan + dry-run ban report
    python3 detect-scrapers.py --enforce            # actually apply/expire bans
    python3 detect-scrapers.py --since 6h
    python3 detect-scrapers.py --allowlist 1.2.3.4,5.6.7.8
    python3 detect-scrapers.py --persist-hours 6 --min-runs 4 --ban-ttl-days 14
    python3 detect-scrapers.py --list-bans          # show active bans and exit
    python3 detect-scrapers.py --unban 1.2.3.4      # lift a ban (needs --enforce)
"""
import sys, os, json, re, subprocess, socket, argparse, datetime

NONBROWSER = re.compile(r"(?i)\b(python-requests|aiohttp|httpx|go-http-client|okhttp|"
                        r"scrapy|libwww-perl|java|node-fetch|axios|wget|curl|got|"
                        r"http\.rb|guzzle|postman|insomnia|restsharp)\b")
# A genuine browser User-Agent: Mozilla/5.0 plus a real rendering-engine token.
# We TRUST these as real users: a long-open browser tab caches its assets, so
# "no page loads in this window" is NOT evidence of a scraper. (This is what
# falsely banned real Firefox users in v1.) Header-spoofing scrapers that fake a
# browser UA are still caught by the hard signals below — duplicate Origin or a
# WS reconnect hot-loop — an accepted trade-off to never ban a real browser.
BROWSER = re.compile(r"(?i)Mozilla/5\.0.*(Gecko|AppleWebKit|Trident)")
WS_HOTLOOP = 500  # WS upgrades in one window above which even a browser UA is treated as a scripted hot-loop
# Verdicts considered unambiguous enough to auto-ban (no real browser does these)
UNAMBIGUOUS = {"WS-SCRAPER", "BOT-UA"}
DOCKER_CHAIN = "DOCKER-USER"

# ---------------------------------------------------------------- log analysis
class Client:
    __slots__ = ("ws","dup","assets","api","ep","ua","first","last","status")
    def __init__(self):
        self.ws=0; self.dup=0; self.assets=0; self.api=0
        self.ep={}; self.ua={}; self.first=None; self.last=None; self.status={}

def parse_logs(container, since):
    cmd = ["docker","logs"] + (["--since", since] if since else []) + [container]
    p = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    return (p.stdout or "") + (p.stderr or "")

def analyze(text):
    ts  = re.compile(r"(\d{2}:\d{2}:\d{2})")
    dts = re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
    clients = {}; span=[None,None]
    for line in text.splitlines():
        i = line.find("handled request")
        if i < 0: continue
        b = line.find("{", i)
        if b < 0: continue
        try: o = json.loads(line[b:])
        except Exception: continue
        r = o.get("request", {})
        ip = r.get("client_ip") or r.get("remote_ip")
        if not ip: continue
        uri = r.get("uri","").split("?")[0]
        h = r.get("headers", {})
        ua = (h.get("User-Agent",["(none)"]) or ["(none)"])[0]
        is_ws = any("websocket" in u.lower() for u in h.get("Upgrade", []))
        c = clients.get(ip) or clients.setdefault(ip, Client())
        m = ts.search(line)
        if m:
            if c.first is None: c.first = m.group(1)
            c.last = m.group(1)
        md = dts.search(line)
        if md:
            d=md.group(1)
            if span[0] is None or d<span[0]: span[0]=d
            if span[1] is None or d>span[1]: span[1]=d
        c.status[o.get("status")] = c.status.get(o.get("status"),0)+1
        c.ua[ua] = c.ua.get(ua,0)+1
        if is_ws:
            c.ws += 1
            if len(h.get("Origin", [])) >= 2: c.dup += 1
        elif uri.startswith("/api/"):
            c.api += 1
            base = re.sub(r"/api/nodes/[0-9a-fA-F]{6,}.*", "/api/nodes/<id>", uri)
            base = re.sub(r"/api/packets/[0-9a-fA-F]{6,}", "/api/packets/<id>", base)
            c.ep[base] = c.ep.get(base,0)+1
        else:
            c.assets += 1
    return clients, span

def verdict(c):
    """(label, confidence, reason) or None for a likely-real user.

    HARD signals (a real browser never produces these) always flag, regardless of
    User-Agent: a forged duplicate Origin header, a non-browser User-Agent, or an
    absurd WebSocket reconnect hot-loop.

    Otherwise, if the client presents a GENUINE browser User-Agent we treat it as a
    real user even when it shows "no page loads" — a long-open tab caches its assets,
    so missing asset fetches is not evidence of scraping. The pure-WS / REST-harvester
    behavioural fingerprints therefore only apply to clients that do NOT look like a
    browser (missing/odd UA). This is the v1.1 fix for falsely banning real browsers.
    """
    ua = max(c.ua, key=c.ua.get) if c.ua else ""
    # --- Hard signals: always a scraper, even with a spoofed browser UA ---
    if c.dup > 0:
        return ("WS-SCRAPER","HIGH","forged duplicate Origin header x%d" % c.dup)
    m = NONBROWSER.search(ua)
    if m:
        return ("BOT-UA","HIGH","non-browser User-Agent (%s)" % m.group(0))
    if c.ws >= WS_HOTLOOP and c.assets == 0:
        return ("WS-SCRAPER","HIGH","WebSocket reconnect hot-loop (%d upgrades, no page load)" % c.ws)
    # --- A real browser presentation is trusted (cached tabs show no fresh page loads) ---
    if BROWSER.search(ua):
        return None
    # --- No browser UA and no hard signal: apply the behavioural fingerprints ---
    if c.ws > 0 and c.api == 0 and c.assets == 0:
        return ("WS-SCRAPER","HIGH","pure WebSocket feed puller, no browser UA (%d upgrades, no page load)" % c.ws)
    if c.assets == 0 and c.ws == 0:
        nodes=c.ep.get("/api/nodes",0)+c.ep.get("/api/nodes/<id>",0)
        regions=c.ep.get("/api/config/regions",0)
        obs=c.ep.get("/api/observers",0)
        skew=c.ep.get("/api/nodes/clock-skew",0)+c.ep.get("/api/observers/clock-skew",0)
        hits=[]
        if nodes>=50:   hits.append("nodes x%d"%nodes)
        if regions>=20: hits.append("config/regions x%d"%regions)
        if obs>=20:     hits.append("observers x%d"%obs)
        if skew>=40:    hits.append("clock-skew x%d"%skew)
        if hits:
            return ("REST-HARVESTER","HIGH","no page load, no WS, no browser UA; harvests "+", ".join(hits))
    return None

def rdns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ""

# ----------------------------------------------------------------- iptables
def _ipt(args, check=False):
    try:
        r = subprocess.run(["sudo","-n","iptables"]+args, capture_output=True, text=True)
        return r.returncode
    except Exception:
        return 1

def ban_rule_exists(ip):
    return _ipt(["-C",DOCKER_CHAIN,"-s",ip,"-j","DROP"]) == 0
def apply_ban_rule(ip):
    if ban_rule_exists(ip): return True
    return _ipt(["-I",DOCKER_CHAIN,"-s",ip,"-j","DROP"]) == 0
def remove_ban_rule(ip):
    ok=True
    while ban_rule_exists(ip):
        if _ipt(["-D",DOCKER_CHAIN,"-s",ip,"-j","DROP"]) != 0: ok=False; break
    return ok

# ----------------------------------------------------------------- state / time
def now(): return datetime.datetime.now()
def iso(dt): return dt.replace(microsecond=0).isoformat()
def parse_iso(s):
    try: return datetime.datetime.fromisoformat(s)
    except Exception: return None
def hours_between(a,b): return abs((a-b).total_seconds())/3600.0

def load_state(path):
    try:
        with open(path) as fh: s=json.load(fh)
    except Exception: s={}
    s.setdefault("tracked",{})   # ip -> {first_flagged,last_flagged,runs,verdict,reason,rdns,unambiguous}
    s.setdefault("bans",{})      # ip -> {banned_at,expires,verdict,reason}
    return s
def save_state(path,s):
    s["updated"]=iso(now())
    try:
        with open(path,"w") as fh: json.dump(s,fh,indent=2)
    except Exception as e:
        print("(warning: could not write state %s: %s)"%(path,e), file=sys.stderr)

def audit(path,msg):
    line="%s  %s"%(iso(now()),msg)
    try:
        with open(path,"a") as fh: fh.write(line+"\n")
    except Exception: pass

# ----------------------------------------------------------------- main
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--container", default="corescope")
    ap.add_argument("--since", default="24h")
    ap.add_argument("--state", default=os.path.expanduser("~/.scraper-state.json"))
    ap.add_argument("--audit", default=os.path.expanduser("~/scraper-bans.log"))
    ap.add_argument("--allowlist", default="", help="comma-separated IPs to never ban")
    ap.add_argument("--allowlist-file", default=os.path.expanduser("~/.scraper-allowlist"),
                    help="file of IPs to never ban/track (one per line, # comments); auto-lifts existing bans")
    ap.add_argument("--persist-hours", type=float, default=6.0)
    ap.add_argument("--min-runs", type=int, default=4)
    ap.add_argument("--grace-hours", type=float, default=2.0, help="forget an IP if not re-flagged within this")
    ap.add_argument("--ban-ttl-days", type=float, default=14.0)
    ap.add_argument("--max-bans-per-run", type=int, default=5)
    ap.add_argument("--enforce", action="store_true", help="actually apply/expire firewall bans (else dry-run)")
    ap.add_argument("--ban-harvesters", action="store_true",
                    help="also auto-ban REST dataset-harvesters (residential/dynamic — collateral risk)")
    ap.add_argument("--no-rdns", action="store_true")
    ap.add_argument("--list-bans", action="store_true")
    ap.add_argument("--unban", default="", help="lift a ban for this IP (with --enforce) and exit")
    ap.add_argument("--ban", action="append", default=[], help="manually ban IP(s) (with --enforce) and exit")
    args=ap.parse_args()

    allow=set(x.strip() for x in args.allowlist.split(",") if x.strip())
    try:
        with open(args.allowlist_file) as fh:
            for line in fh:
                line=line.split("#",1)[0].strip()
                if line: allow.add(line)
    except Exception: pass
    state=load_state(args.state)
    t0=now()

    # --- maintenance-only modes ---
    if args.list_bans:
        if not state["bans"]: print("No active bans."); return 0
        print("Active bans:")
        for ip,b in sorted(state["bans"].items()):
            live = "live" if ban_rule_exists(ip) else "NOT in firewall"
            print("  %-15s  banned %s  expires %s  [%s]  %s" % (ip,b["banned_at"],b["expires"],live,b.get("reason","")))
        return 0
    if args.unban:
        ip=args.unban
        if args.enforce:
            remove_ban_rule(ip); audit(args.audit,"UNBAN %s (manual)"%ip)
        state["bans"].pop(ip,None); save_state(args.state,state)
        print("Unbanned %s%s"%(ip,"" if args.enforce else " (state only; pass --enforce to drop the firewall rule)"))
        return 0
    if args.ban:
        t0=now()
        for ip in args.ban:
            entry={"banned_at":iso(t0),"expires":iso(t0+datetime.timedelta(days=args.ban_ttl_days)),
                   "verdict":"MANUAL","reason":"manual ban"}
            if args.enforce:
                ok=apply_ban_rule(ip); audit(args.audit,"BAN %s MANUAL (expires %s) applied=%s"%(ip,entry["expires"],ok))
                print("Banned %s -> firewall DROP applied=%s, expires %s"%(ip,ok,entry["expires"]))
            else:
                print("Would ban %s (dry-run; pass --enforce to apply)"%ip)
            state["bans"][ip]=entry
        save_state(args.state,state)
        return 0

    text=parse_logs(args.container,args.since)
    if not text.strip():
        print("No logs from `docker logs %s`."%args.container); return 2
    clients,span=analyze(text)

    # Allowlist: never flag/track/ban these; auto-lift any ban they already have.
    for ip in list(allow):
        if ip in state["bans"]:
            if args.enforce: remove_ban_rule(ip); audit(args.audit,"UNBAN %s (allowlisted)"%ip)
            state["bans"].pop(ip,None)
        state["tracked"].pop(ip,None)

    flagged={}     # ip -> (label,conf,reason)
    seen=set(clients)
    real_users=set()
    for ip,c in clients.items():
        if ip in allow: continue
        v=verdict(c)
        if v: flagged[ip]=v
        elif c.assets>0: real_users.add(ip)   # loaded the page = behaving like a human

    # --- update persistence tracking ---
    tr=state["tracked"]
    for ip,(label,conf,reason) in flagged.items():
        rec=tr.get(ip) or {"first_flagged":iso(t0),"runs":0}
        rec["last_flagged"]=iso(t0); rec["runs"]=rec.get("runs",0)+1
        rec["verdict"]=label; rec["reason"]=reason
        rec["unambiguous"]=label in UNAMBIGUOUS
        if not args.no_rdns and not rec.get("rdns"): rec["rdns"]=rdns(ip)
        tr[ip]=rec
    # forget IPs that stopped, or that are now browsing like a real user
    for ip in list(tr):
        last=parse_iso(tr[ip].get("last_flagged",""))
        if ip in real_users and ip not in flagged:
            del tr[ip]; continue
        if last and hours_between(t0,last) > args.grace_hours and ip not in flagged:
            del tr[ip]

    # --- determine ban candidates (unambiguous + persistent + still active) ---
    candidates=[]
    for ip,rec in tr.items():
        eligible = rec.get("unambiguous") or (args.ban_harvesters and rec.get("verdict")=="REST-HARVESTER")
        if not eligible: continue          # REST-harvesters only when --ban-harvesters
        first=parse_iso(rec.get("first_flagged","")); last=parse_iso(rec.get("last_flagged",""))
        if not first or not last: continue
        persisted=hours_between(last,first) >= args.persist_hours
        active=hours_between(t0,last) <= args.grace_hours
        enough=rec.get("runs",0) >= args.min_runs
        if persisted and active and enough and ip not in allow and ip not in state["bans"]:
            candidates.append((ip,rec))
    candidates.sort(key=lambda kv:-kv[1].get("runs",0))

    # --- expire old bans ---
    expired=[]
    for ip,b in list(state["bans"].items()):
        exp=parse_iso(b.get("expires",""))
        if exp and t0>=exp:
            expired.append(ip)
            if args.enforce:
                remove_ban_rule(ip); audit(args.audit,"EXPIRE %s"%ip)
            del state["bans"][ip]
    # re-assert existing bans in firewall (self-heal after reboot/docker restart)
    if args.enforce:
        for ip in state["bans"]:
            if not ban_rule_exists(ip): apply_ban_rule(ip)

    # --- apply (or dry-run) new bans, capped ---
    actioned=[]
    for ip,rec in candidates[:args.max_bans_per_run]:
        exp=iso(t0+datetime.timedelta(days=args.ban_ttl_days))
        entry={"banned_at":iso(t0),"expires":exp,"verdict":rec["verdict"],"reason":rec.get("reason","")}
        if args.enforce:
            ok=apply_ban_rule(ip)
            state["bans"][ip]=entry
            audit(args.audit,"BAN %s  %s | %s  (expires %s)  applied=%s"%(ip,rec["verdict"],rec.get("reason",""),exp,ok))
            actioned.append((ip,rec,"BANNED" if ok else "BAN-FAILED(sudo/iptables?)"))
        else:
            audit(args.audit,"WOULD-BAN %s  %s | %s"%(ip,rec["verdict"],rec.get("reason","")))
            actioned.append((ip,rec,"WOULD BAN (dry-run)"))

    save_state(args.state,state)

    # ----------------------------------------------------------------- report
    mode = "ENFORCE" if args.enforce else "DRY-RUN"
    print("="*74)
    print("  CoreScope scraper scan + auto-ban [%s] — window: last %s"%(mode,args.since))
    if span[0]: print("  log covers: %s..%s UTC (rotation may shorten)"%(span[0],span[1]))
    print("  thresholds: persist>=%gh, runs>=%d, ban TTL=%gd, cap=%d/run"
          %(args.persist_hours,args.min_runs,args.ban_ttl_days,args.max_bans_per_run))
    print("="*74)

    if actioned:
        print("\n### BAN ACTIONS ###")
        for ip,rec,what in actioned:
            print("  %-15s  %-22s %s"%(ip,what,rec.get("reason","")))
    else:
        print("\n  No IPs met the ban threshold this run.")

    # ban-watch: ban-eligible scrapers building toward the threshold
    cand_ips={c[0] for c in candidates}
    watch=[(ip,rec) for ip,rec in tr.items()
           if (rec.get("unambiguous") or (args.ban_harvesters and rec.get("verdict")=="REST-HARVESTER"))
           and ip not in state["bans"] and ip not in cand_ips]
    if watch:
        print("\n### BUILDING TOWARD BAN (unambiguous, not yet persistent enough) ###")
        for ip,rec in sorted(watch,key=lambda kv:-kv[1].get("runs",0))[:12]:
            f=parse_iso(rec["first_flagged"])
            age=hours_between(t0,f) if f else 0
            print("  %-15s  %4.1fh / %gh   runs=%d  %s  %s"
                  %(ip,age,args.persist_hours,rec.get("runs",0),rec.get("verdict",""),(rec.get("rdns") or "")[:32]))

    # current REST harvesters (reported, never auto-banned)
    harv=[ip for ip,(l,c,r) in flagged.items() if l=="REST-HARVESTER"]
    if harv:
        hdr = "REST HARVESTERS (ban-eligible)" if args.ban_harvesters else "REST HARVESTERS (recommend-only — not auto-banned)"
        print("\n### %s ###" % hdr)
        for ip in harv:
            print("  %-15s  %s  %s"%(ip,flagged[ip][2],(tr.get(ip,{}).get("rdns") or rdns(ip) if not args.no_rdns else "")))

    if state["bans"]:
        print("\n### ACTIVE BANS (%d) ###"%len(state["bans"]))
        for ip,b in sorted(state["bans"].items()):
            print("  %-15s  until %s  %s"%(ip,b["expires"],b.get("reason","")))
    if expired:
        print("\n  Expired/lifted this run: %s"%", ".join(expired))

    print("\n"+"-"*74)
    print("  state: %s   audit: %s"%(args.state,args.audit))
    if not args.enforce:
        print("  DRY-RUN — nothing was banned. Add --enforce (and ensure passwordless sudo) to act.")
    print("-"*74)
    return 1 if actioned else 0

if __name__=="__main__":
    sys.exit(main())
