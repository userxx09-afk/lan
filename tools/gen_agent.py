"""Copies the WinRM inventory script into the agent, so the agent and the agentless scan collect the same data.
Run after changing netinv/collectors/winrm.py ENDPOINT_SCRIPT:  python tools/gen_agent.py   (CI: --check)"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from netinv.collectors.winrm import ENDPOINT_SCRIPT  # noqa: E402

AGENT = ROOT / "netinv" / "agent" / "NetInventoryAgent.ps1"
START = "#region inventory (generated from netinv/collectors/winrm.py ENDPOINT_SCRIPT by tools/gen_agent.py: do not edit here)\n"
END = "#endregion"


def body() -> str:
    s = ENDPOINT_SCRIPT.strip("\n")
    s = s.replace("__CHECK_PENDING__", "$CheckPendingArg").replace("__LOGON_DAYS__", "$LogonDaysArg")
    s = s.replace("source = 'winrm'", "source = 'agent'; agent_version = $AgentVersion")
    inner = "\n".join(("    " + ln) if ln.strip() else "" for ln in s.split("\n"))
    return "function Get-Inventory([bool]$CheckPendingArg, [int]$LogonDaysArg) {\n" + inner + "\n}\n"


def main() -> int:
    text = AGENT.read_text(encoding="utf-8")
    i, j = text.index(START) + len(START), text.index(END, text.index(START))
    new = text[:i] + body() + text[j:]
    if "--check" in sys.argv:
        if new != text:
            print("netinv/agent/NetInventoryAgent.ps1 is out of date: run python tools/gen_agent.py")
            return 1
        print("agent inventory script is up to date")
        return 0
    AGENT.write_text(new, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
