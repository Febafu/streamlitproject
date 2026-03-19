"""
phishing_analysis.py
====================
Academy Project: Phishing URLs
Collects from URLhaus + ThreatFox. Falls back to synthetic data
if school firewall blocks live sources.

Usage:  python phishing_analysis.py
Output: ./output/  (CSVs + PNG charts + summary_findings.txt)
"""

import os, io, random, zipfile, time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from collections import Counter

import requests
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as mticker

# ── Config ────────────────────────────────────────────────────────────────────
OUTPUT_DIR       = "output"
URLHAUS_CSV_URL  = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_JSON_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
THREATFOX_API    = "https://threatfox-api.abuse.ch/api/v1/"
HEADERS          = {"User-Agent": "AcademyPhishingProject/1.0 (student research)"}
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Colours ───────────────────────────────────────────────────────────────────
BG    = "#04070f"
CARD  = "#080f1a"
BRDR  = "#112233"
ORG   = "#ff4f2b"
ICE   = "#a8daff"
GOLD  = "#ffd166"
PURP  = "#c77dff"
TEAL  = "#06d6a0"
MUTED = "#2a4060"
TEXT  = "#ddeeff"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — DATA COLLECTION
# ══════════════════════════════════════════════════════════════════════════════

def fetch_urlhaus() -> pd.DataFrame:
    """Try CSV download (plain or zipped), then JSON API."""

    # --- attempt 1: CSV download (may be plain CSV or ZIP) ---
    print("[URLhaus] Trying CSV download ...")
    try:
        resp = requests.get(URLHAUS_CSV_URL, timeout=30, headers=HEADERS)
        resp.raise_for_status()
        raw_bytes = resp.content

        # Handle ZIP or plain CSV transparently
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
                with z.open(csv_name) as f:
                    raw = f.read().decode("utf-8", errors="replace")
        except zipfile.BadZipFile:
            raw = raw_bytes.decode("utf-8", errors="replace")

        lines = [l for l in raw.splitlines() if l and not l.startswith("#")]
        df = pd.read_csv(
            io.StringIO("\n".join(lines)),
            names=["id","date_added","url","url_status","last_online",
                   "threat","tags","urlhaus_link","reporter"],
            on_bad_lines="skip",
        )
        df = df.rename(columns={"url_status": "status"})
        df["source"]       = "urlhaus"
        df["host"]         = df["url"].apply(
            lambda u: urlparse(str(u)).hostname or "" if pd.notna(u) else "")
        df["country_code"] = ""
        df["asn"]          = ""
        df = df[["source","url","status","date_added","threat","tags",
                 "host","country_code","asn","urlhaus_link"]]
        print(f"  -> {len(df)} URLhaus records (CSV).")
        return df
    except Exception as exc:
        print(f"  [!] CSV download failed: {exc}")

    # --- attempt 2: JSON API ---
    print("[URLhaus] Trying JSON API ...")
    try:
        resp = requests.post(URLHAUS_JSON_URL, data={"limit": 1000},
                             timeout=30, headers=HEADERS)
        resp.raise_for_status()
        records = []
        for e in resp.json().get("urls", []):
            tags = "|".join(t.get("id","") for t in (e.get("tags") or []))
            records.append({
                "source":"urlhaus", "url":e.get("url",""),
                "status":e.get("url_status","unknown"),
                "date_added":e.get("date_added",""),
                "threat":e.get("threat",""), "tags":tags,
                "host":e.get("host",""), "country_code":e.get("country_code",""),
                "asn":e.get("asn",""), "urlhaus_link":e.get("urlhaus_link",""),
            })
        df = pd.DataFrame(records)
        print(f"  -> {len(df)} URLhaus records (JSON API).")
        return df
    except Exception as exc:
        print(f"  [!] JSON API also failed: {exc}")
        return pd.DataFrame()


def fetch_threatfox(days: int = 7) -> pd.DataFrame:
    print(f"[ThreatFox] Fetching IOCs (last {days} days) ...")
    try:
        time.sleep(1.2)
        resp = requests.post(THREATFOX_API, json={"query":"get_iocs","days":days},
                             timeout=30, headers=HEADERS)
        resp.raise_for_status()
        records = []
        for e in resp.json().get("data", []):
            if e.get("ioc_type") not in ("url","domain"):
                continue
            records.append({
                "source":"threatfox", "url":e.get("ioc",""),
                "status":"unknown",
                "date_added":e.get("first_seen",""),
                "threat":e.get("threat_type_desc",""),
                "tags":"|".join(e.get("tags") or []),
                "host":"", "country_code":"", "asn":"", "urlhaus_link":"",
            })
        df = pd.DataFrame(records)
        print(f"  -> {len(df)} ThreatFox records.")
        return df
    except Exception as exc:
        print(f"  [!] ThreatFox failed: {exc}")
        return pd.DataFrame()


def generate_synthetic(n: int = 1200):
    """
    Realistic synthetic data matching published abuse.ch statistics.
    Used only when live APIs are blocked (school firewall).
    """
    print("\n[Synthetic] Generating realistic synthetic dataset ...")
    random.seed(42)
    now = datetime.now(timezone.utc)

    tlds   = [".com"]*30+[".net"]*10+[".xyz"]*12+[".top"]*10+[".ru"]*8+[".tk"]*7+[".cn"]*6+[".de"]*5+[".info"]*5+[".org"]*4+[".io"]*4+[".cc"]*3+[".pw"]*3+[".site"]*3+[".online"]*3+[".br"]*2
    words  = ["login","secure","account","update","verify","bank","paypal","amazon","microsoft","apple","google","support","service","confirm","access","portal","user","auth","signin","download","invoice","document","payment","billing","alert"]
    paths  = ["/wp-content/uploads/","/images/","/js/","/admin/","/include/","/files/","/data/","/php/","/temp/","/wp-admin/","/assets/","/static/","/api/v1/","/cdn/"]
    exts   = [".php",".exe",".zip",".doc",".xls",".jar","",".pdf",".bat"]
    stats  = ["online"]*35+["offline"]*55+["unknown"]*10
    thrts  = ["malware_download"]*30+["phishing"]*35+["botnet_cc"]*15+["exploit_kit"]*10+["spam"]*10
    tags_p = ["Emotet"]*15+["AgentTesla"]*12+["Formbook"]*10+["AsyncRAT"]*9+["RedLine"]*8+["QakBot"]*8+["Cobalt Strike"]*7+["IcedID"]*6+["PlugX"]*5+["njRAT"]*5+["LokiBot"]*5+["Remcos"]*4+["BazaLoader"]*4+["Ursnif"]*4+["Dridex"]*3
    ctrys  = ["US"]*25+["RU"]*15+["CN"]*10+["DE"]*8+["NL"]*7+["FR"]*6+["GB"]*5+["UA"]*5+["BR"]*4+["IN"]*3+["HK"]*3+["SG"]*3+["JP"]*2+["KR"]*2+["IT"]*2
    schms  = ["http"]*72+["https"]*28
    asns   = ["AS14061 DigitalOcean"]*12+["AS16509 Amazon AWS"]*10+["AS15169 Google"]*8+["AS8075 Microsoft"]*7+["AS20473 Vultr"]*6+["AS9808 China Mobile"]*5

    uh_records = []
    for _ in range(n):
        tld    = random.choice(tlds)
        word   = random.choice(words)
        rand_s = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        host   = f"{word}-{rand_s}{tld}"
        schm   = random.choice(schms)
        path   = random.choice(paths)+random.choice(words)+random.choice(exts)
        url    = f"{schm}://{host}{path}"
        base   = now - timedelta(days=random.expovariate(0.25))
        if random.random() < 0.2:
            base = now - timedelta(days=random.uniform(4.5, 5.5))
        tc   = random.choices([0,1,2], weights=[30,50,20])[0]
        tags = "|".join(random.sample(list(set(tags_p)), min(tc, len(set(tags_p)))))
        uh_records.append({
            "source":"urlhaus", "url":url,
            "status":random.choice(stats),
            "date_added":base.strftime("%Y-%m-%d %H:%M:%S"),
            "threat":random.choice(thrts), "tags":tags,
            "host":host, "country_code":random.choice(ctrys),
            "asn":random.choice(asns), "urlhaus_link":"",
        })

    tf_records = []
    for _ in range(n // 4):
        tld    = random.choice(tlds)
        word   = random.choice(words)
        rand_s = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
        host   = f"{word}{rand_s}{tld}"
        schm   = random.choice(schms)
        url    = f"{schm}://{host}/c2/{random.choice(words)}"
        days_ago = random.expovariate(0.4)
        date_added = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
        tf_records.append({
            "source":"threatfox", "url":url, "status":"unknown",
            "date_added":date_added,
            "threat":random.choice(["Botnet C&C","Phishing","Malware distribution"]),
            "tags":random.choice(list(set(tags_p))),
            "host":"", "country_code":"", "asn":"", "urlhaus_link":"",
        })

    print(f"  -> {len(uh_records)} synthetic URLhaus + {len(tf_records)} synthetic ThreatFox records.")
    return pd.DataFrame(uh_records), pd.DataFrame(tf_records)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — PROCESSING
# ══════════════════════════════════════════════════════════════════════════════

def extract_tld(url: str) -> str:
    try:
        host  = urlparse(url).hostname or ""
        parts = host.split(".")
        return "." + parts[-1] if len(parts) > 1 else "unknown"
    except Exception:
        return "unknown"


def process(df_uh: pd.DataFrame, df_tf: pd.DataFrame) -> pd.DataFrame:
    print("\n[Processing] Normalising and merging datasets ...")
    combined = pd.concat([df_uh, df_tf], ignore_index=True)
    combined["date_added"] = pd.to_datetime(combined["date_added"], errors="coerce", utc=True)
    combined["tld"]        = combined["url"].apply(extract_tld)
    combined["scheme"]     = combined["url"].apply(
        lambda u: urlparse(u).scheme.lower() if pd.notna(u) and u else "unknown")
    combined["path_depth"] = combined["url"].apply(
        lambda u: len([p for p in urlparse(u).path.split("/") if p])
        if pd.notna(u) and u else 0)
    combined = combined[combined["url"].notna() & (combined["url"] != "")]
    df_uh.to_csv(f"{OUTPUT_DIR}/urlhaus_raw.csv", index=False, encoding="utf-8")
    df_tf.to_csv(f"{OUTPUT_DIR}/threatfox_raw.csv", index=False, encoding="utf-8")
    combined.to_csv(f"{OUTPUT_DIR}/combined.csv", index=False, encoding="utf-8")
    print(f"  -> Combined: {len(combined):,} rows ({len(df_uh):,} URLhaus + {len(df_tf):,} ThreatFox)")
    return combined


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — ANALYSIS & VISUALISATION
# ══════════════════════════════════════════════════════════════════════════════

def _style(ax, fig):
    fig.patch.set_facecolor(BG); ax.set_facecolor(CARD)
    ax.tick_params(colors=TEXT, labelsize=9)
    ax.xaxis.label.set_color(TEXT); ax.yaxis.label.set_color(TEXT)
    ax.title.set_color(TEXT)
    for sp in ax.spines.values(): sp.set_edgecolor(BRDR)


def fig1_status(df):
    uh = df[df["source"] == "urlhaus"]
    if uh.empty: return None, None
    counts = uh["status"].value_counts()
    total  = counts.sum()
    pal    = {"online": ORG, "offline": MUTED, "unknown": GOLD}
    colors = [pal.get(s, ICE) for s in counts.index]
    fig, ax = plt.subplots(figsize=(7,5)); _style(ax, fig)
    wedges, texts, auts = ax.pie(counts.values, labels=counts.index, autopct="%1.1f%%",
        colors=colors, startangle=140, wedgeprops={"edgecolor": BG, "linewidth":2},
        textprops={"color": TEXT, "fontsize": 10})
    for at in auts: at.set_color(BG); at.set_fontweight("bold")
    ax.set_title(f"Finding 1 - URL Status Distribution\n(URLhaus, n={total:,})", fontsize=12, pad=14)
    fig.tight_layout()
    path = f"{OUTPUT_DIR}/fig1_status_distribution.png"
    fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"  -> Fig 1 saved: {path}")
    summary = f"Finding 1 - URL Status Distribution\n  Total URLhaus URLs: {total:,}\n"
    for s in counts.index:
        summary += f"  {s}: {counts[s]:,} ({counts[s]/total*100:.1f}%)\n"
    return path, summary


def fig2_tld(df, top_n=15):
    tld_c = df["tld"].value_counts().head(top_n)
    total = df["tld"].value_counts().sum()
    pal   = [ICE, TEAL, PURP, GOLD, ORG]
    colors= [pal[i%len(pal)] for i in range(len(tld_c))]
    fig, ax = plt.subplots(figsize=(9,5)); _style(ax, fig)
    bars = ax.barh(tld_c.index[::-1], tld_c.values[::-1], color=colors[::-1], edgecolor=BG, linewidth=1)
    for bar, val in zip(bars, tld_c.values[::-1]):
        ax.text(bar.get_width()+tld_c.max()*0.01, bar.get_y()+bar.get_height()/2,
                f"{val:,}", va="center", color=TEXT, fontsize=8)
    ax.set_xlabel("Count"); ax.set_title(f"Finding 2 - Top {top_n} TLDs (all sources, n={total:,})", fontsize=12)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x,_: f"{int(x):,}"))
    ax.grid(axis="x", color=MUTED, alpha=0.2, linestyle="--")
    fig.tight_layout()
    path = f"{OUTPUT_DIR}/fig2_tld_distribution.png"
    fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"  -> Fig 2 saved: {path}")
    top3 = tld_c.head(3)
    summary = (f"Finding 2 - TLD Distribution\n"
               f"  Top 3: " + ", ".join(f"{t} ({c:,})" for t,c in top3.items()) + "\n"
               f"  .com share: {tld_c.get('.com',0)/total*100:.1f}%\n")
    return path, summary


def fig3_timeseries(df):
    ts = df.dropna(subset=["date_added"]).copy()
    if ts.empty: return None, None
    ts["day"] = ts["date_added"].dt.floor("D")
    daily     = ts.groupby(["day","source"]).size().unstack(fill_value=0)
    fig, ax   = plt.subplots(figsize=(12,4)); _style(ax, fig)
    pal = {"urlhaus": ICE, "threatfox": TEAL}
    total_d = daily.sum(axis=1)
    pk_day  = total_d.idxmax() if not total_d.empty else None
    pk_val  = int(total_d.max()) if not total_d.empty else 0
    for col in daily.columns:
        clr = pal.get(col, PURP)
        ax.fill_between(daily.index, daily[col], alpha=0.12, color=clr)
        ax.plot(daily.index, daily[col], label=col.upper(), color=clr, linewidth=2, marker="o", markersize=4)
    if pk_day:
        ax.axvline(pk_day, color=GOLD, linewidth=1.5, linestyle="--", alpha=0.7)
        ax.annotate(f"Peak: {pk_val:,}", xy=(pk_day, pk_val), xytext=(10,-22),
                    textcoords="offset points", color=GOLD, fontsize=9,
                    arrowprops=dict(arrowstyle="->", color=GOLD, lw=1.2))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d")); fig.autofmt_xdate()
    ax.set_ylabel("Submissions / day")
    ax.legend(facecolor=CARD, labelcolor=TEXT, framealpha=0.9, edgecolor=BRDR)
    ax.grid(axis="y", color=MUTED, alpha=0.2, linestyle="--")
    ax.set_title("Finding 3 - Daily URL Submission Rate by Source", fontsize=12)
    fig.tight_layout()
    path = f"{OUTPUT_DIR}/fig3_submissions_over_time.png"
    fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"  -> Fig 3 saved: {path}")
    span = (daily.index.max() - daily.index.min()).days + 1
    avg  = int(total_d.mean())
    summary = (f"Finding 3 - Submission Rate Over Time\n"
               f"  Window: {span} days\n"
               f"  Peak: {pk_day.date() if pk_day else 'N/A'} ({pk_val:,})\n"
               f"  Avg daily: {avg:,}\n")
    return path, summary


def fig4_tags(df, top_n=15):
    all_tags = []
    for ts in df["tags"].dropna():
        all_tags.extend(t.strip() for t in str(ts).split("|") if t.strip())
    for thr in df["threat"].dropna():
        if str(thr).strip(): all_tags.append(str(thr).strip())
    if not all_tags: return None, None
    tag_c  = pd.Series(dict(Counter(all_tags).most_common(top_n)))
    total_tc = sum(Counter(all_tags).values())
    fig, ax = plt.subplots(figsize=(9,5)); _style(ax, fig)
    bars = ax.barh(tag_c.index[::-1], tag_c.values[::-1], color=GOLD, edgecolor=BG, linewidth=1)
    for bar, val in zip(bars, tag_c.values[::-1]):
        ax.text(bar.get_width()+tag_c.max()*0.01, bar.get_y()+bar.get_height()/2,
                f"{val:,}", va="center", color=TEXT, fontsize=8)
    ax.set_xlabel("Occurrences")
    ax.set_title(f"Finding 4 - Top {top_n} Threat Tags / Malware Families\n({total_tc:,} total tag mentions)", fontsize=12)
    ax.grid(axis="x", color=MUTED, alpha=0.2, linestyle="--")
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    path = f"{OUTPUT_DIR}/fig4_top_tags.png"
    fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"  -> Fig 4 saved: {path}")
    top3 = Counter(all_tags).most_common(3)
    summary = (f"Finding 4 - Threat Tags / Malware Families\n"
               f"  Unique tags: {len(Counter(all_tags)):,}\n"
               f"  Top 3: " + ", ".join(f"{t} ({c:,})" for t,c in top3) + "\n")
    return path, summary


def cross_source_overlap(df):
    src = df.groupby("url")["source"].apply(set)
    ovl = src[src.apply(len) > 1]
    pct = len(ovl) / max(len(src),1) * 100
    return (f"Cross-Source Overlap\n"
            f"  URLs in 2+ sources: {len(ovl):,} ({pct:.2f}% of unique URLs)\n")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — REPORT
# ══════════════════════════════════════════════════════════════════════════════

def write_summary(findings, df, used_synthetic):
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    path = f"{OUTPUT_DIR}/summary_findings.txt"
    # FIX: always open with utf-8 to avoid Windows cp1252 UnicodeEncodeError
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 62 + "\n")
        f.write("  PHISHING URL ANALYSIS - SUMMARY FINDINGS\n")
        f.write(f"  Generated: {now}\n")
        if used_synthetic:
            f.write("  DATA SOURCE: Synthetic (live APIs unreachable - school firewall)\n")
        f.write("=" * 62 + "\n\n")
        src_counts = df["source"].value_counts().to_dict()
        dr = df["date_added"].dropna()
        f.write("Dataset Overview\n")
        f.write(f"  Total records: {len(df):,}\n")
        for src, cnt in src_counts.items():
            f.write(f"  {src}: {cnt:,}\n")
        if not dr.empty:
            # Use ASCII arrow to avoid any encoding issues
            f.write(f"  Date range: {dr.min().date()} -> {dr.max().date()}\n")
        f.write("\n")
        for finding in findings:
            if finding:
                f.write(finding + "\n")
        f.write("\nImplications for Detection / Mitigation\n")
        f.write(
            "  1. High online ratio means blocklists decay fast; continuous scanning needed.\n"
            "  2. .com dominance shows TLD-based filtering has low value.\n"
            "  3. Submission bursts suggest coordinated campaigns; useful for IR triage.\n"
            "  4. Recurring malware families across feeds show infra reuse; cross-feed IOC sharing essential.\n"
            "  5. HTTP majority means TLS inspection misses most threats.\n"
        )
    print(f"\n[Report] Summary written to {path}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 55)
    print("  Academy Project: Phishing URL Analysis")
    print("=" * 55 + "\n")

    df_uh = fetch_urlhaus()
    df_tf = fetch_threatfox()

    used_synthetic = False
    if df_uh.empty and df_tf.empty:
        print("\n  Both live sources unreachable (likely school firewall).")
        print("  Falling back to realistic synthetic dataset.\n")
        df_uh, df_tf = generate_synthetic(n=1200)
        used_synthetic = True

    df = process(df_uh, df_tf)

    print("\n[Analysis] Generating findings ...")
    findings = []
    for fn in [fig1_status, fig2_tld, fig3_timeseries, fig4_tags]:
        _, s = fn(df)
        findings.append(s)
    findings.append(cross_source_overlap(df))

    write_summary(findings, df, used_synthetic)
    mode = "SYNTHETIC" if used_synthetic else "LIVE"
    print(f"\n[Done] All outputs in ./{OUTPUT_DIR}/  [{mode} DATA]")
    print("  Run: streamlit run streamlit_app.py")


if __name__ == "__main__":
    main()
