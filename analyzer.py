import time
import json
import sqlite3
import requests
import os
from datetime import datetime, timedelta

# ── Konfigurasi ──────────────────────────────────────────────
LOG_PATH       = "/var/log/nginx/shared/threat_alert.log"
DB_PATH        = "/app/db/threats.db"
WEBHOOK_URL    = os.getenv("N8N_WEBHOOK_URL", "")
SCORE_LIMIT    = 100
RETENTION_DAYS = 30

# Bobot ancaman: Dimensi 1 — Target (endpoint yang diakses)
TARGET_WEIGHTS = {
    ".env":         50,
    ".git":         40,
    "wp-admin":     30,
    "wp-login.php": 30,
    "phpMyAdmin":   35,
    "admin":        20,
}

# Bobot ancaman: Dimensi 2 — Alat (User-Agent)
UA_WEIGHTS = {
    "sqlmap":          40,
    "nikto":           35,
    "nmap":            30,
    "masscan":         30,
    "zgrab":           25,
    "nuclei":          30,
    "dirbuster":       25,
    "gobuster":        25,
    "python-requests": 10,
    "curl":            5,
}

# ── Setup Database ────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip         TEXT PRIMARY KEY,
            score      INTEGER DEFAULT 0,
            last_seen  TEXT,
            reported   INTEGER DEFAULT 0
        )
    """)
    con.commit()
    return con

# ── Hitung Skor Ancaman ───────────────────────────────────────
def calculate_score(uri: str, user_agent: str, is_tool: int) -> int:
    score = 0

    # Dimensi 1: Target
    for target, weight in TARGET_WEIGHTS.items():
        if target in uri:
            score += weight
            break

    # Dimensi 2: Alat
    # [UPGRADE] Kalau Nginx sudah flag via map $is_hacking_tool,
    # langsung kasih bonus 30 poin tanpa parse UA lagi
    if is_tool == 1:
        score += 30
    else:
        for tool, weight in UA_WEIGHTS.items():
            if tool.lower() in user_agent.lower():
                score += weight
                break

    return score

# ── Update & Cek Score IP ────────────────────────────────────
def update_ip_score(con, ip: str, delta: int) -> dict:
    now = datetime.utcnow().isoformat()
    con.execute("""
        INSERT INTO ip_scores (ip, score, last_seen, reported)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(ip) DO UPDATE SET
            score     = score + excluded.score,
            last_seen = excluded.last_seen
    """, (ip, delta, now))
    con.commit()
    row = con.execute(
        "SELECT score, reported FROM ip_scores WHERE ip = ?", (ip,)
    ).fetchone()
    return {"score": row[0], "reported": row[1]}

# ── Kirim Sinyal ke n8n ──────────────────────────────────────
def trigger_webhook(ip: str, score: int):
    if not WEBHOOK_URL:
        print(f"[WARN] WEBHOOK_URL belum di-set. Skip trigger untuk {ip}")
        return
    try:
        resp = requests.post(WEBHOOK_URL, json={
            "ip_address": ip,
            "score":      score,
            "timestamp":  datetime.utcnow().isoformat()
        }, timeout=5)
        print(f"[ALERT] Webhook terkirim untuk {ip} (skor: {score}) → {resp.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Gagal kirim webhook: {e}")

# ── Hapus Data Lama ──────────────────────────────────────────
def cleanup_old_records(con):
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    con.execute("DELETE FROM ip_scores WHERE last_seen < ?", (cutoff,))
    con.commit()

# ── Baca Log Real-time ───────────────────────────────────────
def tail_log(filepath: str):
    # Tunggu sampai file log dibuat oleh Nginx
    while not os.path.exists(filepath):
        print(f"[WAIT] File {filepath} belum ada, coba lagi 2 detik...")
        time.sleep(2)
    print(f"[OK] File {filepath} ditemukan, mulai baca log...")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)

# ── Main Loop ────────────────────────────────────────────────
def main():
    print("[START] Python Analyzer aktif...")
    con = init_db()
    cleanup_counter = 0

    for raw_line in tail_log(LOG_PATH):
        try:
            entry      = json.loads(raw_line)
            ip         = entry.get("ip", "")
            uri        = entry.get("uri", "")
            user_agent = entry.get("ua", "")
            is_tool    = int(entry.get("tool", 0))  # [UPGRADE] field baru dari Nginx

            if not ip:
                continue

            delta  = calculate_score(uri, user_agent, is_tool)
            result = update_ip_score(con, ip, delta)

            print(f"[LOG] {ip} | +{delta} poin | Total: {result['score']}")

            if result["score"] >= SCORE_LIMIT and result["reported"] == 0:
                trigger_webhook(ip, result["score"])
                con.execute(
                    "UPDATE ip_scores SET reported = 1 WHERE ip = ?", (ip,)
                )
                con.commit()

        except json.JSONDecodeError:
            print(f"[WARN] Bukan JSON valid, skip: {raw_line[:80]}")
        except Exception as e:
            print(f"[ERROR] {e}")

        cleanup_counter += 1
        if cleanup_counter >= 1000:
            cleanup_old_records(con)
            cleanup_counter = 0

if __name__ == "__main__":
    main()