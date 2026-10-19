#!/usr/bin/env python3
"""Answer the HW 3.1 questions from Zeek TSV logs in the current folder.
usage: python3 analyze_zeek.py  (run inside the folder holding conn.log, dns.log, ...)"""
import csv, collections, ipaddress, statistics, os, datetime

def load(name):
    if not os.path.exists(name):
        return []
    rows, fields = [], None
    with open(name) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            else:
                rows.append(dict(zip(fields, line.split("\t"))))
    return rows

def internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_multicast
    except ValueError:
        return False

def utc(ts):
    return datetime.datetime.fromtimestamp(float(ts), datetime.timezone.utc).strftime("%H:%M:%S")

def num(x):
    return 0 if x in ("-", "", None) else int(x)

conn, dns, http, ssl, x509, files, notice, weird = (load(n) for n in
    ["conn.log", "dns.log", "http.log", "ssl.log", "x509.log", "files.log", "notice.log", "weird.log"])
C = collections.Counter
print("== log line counts:", {n: len(v) for n, v in zip(
    ["conn", "dns", "http", "ssl", "x509", "files", "notice", "weird"], [conn, dns, http, ssl, x509, files, notice, weird])})

print("\n== Q1 CONNECTIONS")
ips = {r["id.orig_h"] for r in conn} | {r["id.resp_h"] for r in conn}
ints = sorted(i for i in ips if internal(i))
print("internal (RFC1918) IPs:", len(ints), ints)
ext = C(r["id.resp_h"] for r in conn if not internal(r["id.resp_h"]) and not ipaddress.ip_address(r["id.resp_h"]).is_multicast)
print("top external dest by #connections:", ext.most_common(8))
print("proto:", C(r["proto"] for r in conn).most_common())
print("service:", C(r["service"] for r in conn).most_common())
print("resp_p:", C(r["id.resp_p"] + "/" + r["proto"] for r in conn).most_common(10))

print("\n== Q2 DNS")
q = C(r["query"] for r in dns)
print("unique queries:", len(q))
for d, n in q.most_common():
    ans = sorted({a for r in dns if r["query"] == d for a in r["answers"].split(",") if a != "-"})
    print(f"  {n:4d}  {d:55s} {','.join(ans)[:70]}")

print("\n== Q3 HTTP")
for r in http:
    print(" ", utc(r["ts"]), r["id.orig_h"], "->", r["id.resp_h"], r["method"], r["host"], r["uri"][:60],
          r["status_code"], r.get("user_agent", "")[:30], "resp_mime=" + r.get("resp_mime_types", ""),
          "resp_len=" + r.get("response_body_len", ""))
print("files.log:", [(f.get("mime_type"), f.get("total_bytes") or f.get("seen_bytes"), f.get("source"),
                      f.get("sha1", "")) for f in files])

print("\n== Q4 SSL/TLS")
print("ssl sessions:", len(ssl), "established:", C(r.get("established") for r in ssl))
print("versions:", C(r.get("version") for r in ssl).most_common())
print("SNI:", C(r.get("server_name") for r in ssl).most_common(12))
print("validation_status:", C(r.get("validation_status", "") for r in ssl).most_common())
for r in x509:
    if r.get("certificate.subject") == r.get("certificate.issuer"):
        print("  SELF-SIGNED cert:", r.get("certificate.subject"), "| valid",
              utc(r["certificate.not_valid_before"]) if r.get("certificate.not_valid_before") not in (None, "-") else "")
subj = C((r.get("certificate.subject"), r.get("certificate.issuer")) for r in x509)
print("x509 subjects:", subj.most_common(6))

print("\n== Q5 BEHAVIOR")
by = collections.defaultdict(list)
for r in conn:
    by[(r["id.resp_h"], r["id.resp_p"])].append(float(r["ts"]))
for k, ts in sorted(by.items(), key=lambda kv: -len(kv[1]))[:10]:
    ts.sort(); d = [b - a for a, b in zip(ts, ts[1:])]
    if len(d) > 2:
        print(f"  {k[0]}:{k[1]} n={len(ts)} mean={statistics.mean(d):.1f}s median={statistics.median(d):.1f}s stdev={statistics.pstdev(d):.1f}")
print("longest connections:")
for r in sorted(conn, key=lambda r: -float(r["duration"]) if r["duration"] != "-" else 0)[:6]:
    print(f"  {r['id.orig_h']}->{r['id.resp_h']}:{r['id.resp_p']} {r['service']} dur={float(r['duration']):.0f}s "
          f"orig={r['orig_bytes']} resp={r['resp_bytes']} state={r['conn_state']}")
print("largest uploads (orig_bytes):")
for r in sorted(conn, key=lambda r: -num(r["orig_bytes"]))[:6]:
    print(f"  {r['id.orig_h']}->{r['id.resp_h']}:{r['id.resp_p']} {r['service']} orig={r['orig_bytes']} resp={r['resp_bytes']}")
print("largest downloads (resp_bytes):")
for r in sorted(conn, key=lambda r: -num(r["resp_bytes"]))[:6]:
    print(f"  {r['id.orig_h']}->{r['id.resp_h']}:{r['id.resp_p']} {r['service']} orig={r['orig_bytes']} resp={r['resp_bytes']}")
def internet(ip):
    a = ipaddress.ip_address(ip)
    return a.is_global and not a.is_multicast
tot_up = sum(num(r["orig_bytes"]) for r in conn if internal(r["id.orig_h"]) and internet(r["id.resp_h"]))
tot_dn = sum(num(r["resp_bytes"]) for r in conn if internal(r["id.orig_h"]) and internet(r["id.resp_h"]))
print(f"total to Internet: up={tot_up} B  down={tot_dn} B")
print("notice:", [(r.get("note"), r.get("msg")) for r in notice])
print("weird:", C(r.get("name") for r in weird).most_common(8))
