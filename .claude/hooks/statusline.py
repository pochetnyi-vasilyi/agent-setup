#!/usr/bin/env python3
"""Claude Code status line: dir >> branch >> model >> context% >> rate limits"""
import json
import os
import subprocess
import sys
from pathlib import Path

# Traffic-light colors — Claude-branded (warm earth)
GREEN = "\033[38;2;110;176;90m"    # leaf  #6eb05a
YELLOW = "\033[38;2;224;164;88m"   # amber #e0a458
RED = "\033[38;2;192;57;43m"       # brick #c0392b


def get_branch(project_dir: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", project_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=1
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def format_bar(pct: float, width: int = 7) -> str:
    """Build colored progress bar: [####---]"""
    filled = round(pct / 100 * width)
    filled = max(0, min(filled, width))

    # Color by usage level (with ~15% overhead for system prompt/tools)
    total_pct = pct + 15
    if total_pct < 50:
        color = GREEN
    elif total_pct < 80:
        color = YELLOW
    else:
        color = RED

    D = "\033[2m"   # dim
    R = "\033[0m"   # reset
    bar_filled = "#" * filled
    bar_empty = "-" * (width - filled)
    return f"{color}[{bar_filled}{D}{bar_empty}{R}{color}]{R}", color


def main():
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except Exception:
        print("⚠ parse error")
        return

    # Debug: dump input to file (set DEBUG_STATUSLINE=1)
    if os.getenv("DEBUG_STATUSLINE"):
        debug_path = Path("/tmp/claude-statusline-debug.json")
        debug_path.write_text(json.dumps(data, indent=2, default=str))

    project_dir = data.get("workspace", {}).get("project_dir", "")
    model = data.get("model", {}).get("display_name", "?")
    session_name = data.get("session_name", "")
    branch = get_branch(project_dir)

    # Context info — prefer new API fields, fallback to context_window
    ctx_window = data.get("context_window", {})
    pct = ctx_window.get("used_percentage")

    # Rate limits (Claude.ai Pro/Max only)
    rate_limits = data.get("rate_limits", {})
    five_hour = rate_limits.get("five_hour", {})
    seven_day = rate_limits.get("seven_day", {})

    # Project folder name
    folder = Path(project_dir).name if project_dir else ""

    # ANSI colors — Claude-branded palette (warm earth)
    D = "\033[2m"   # dim
    R = "\033[0m"   # reset
    SEP = f" {D}>>{R} "
    FOLDER = "\033[38;2;235;219;188m"  # manilla cream
    BRANCH = "\033[38;2;212;162;127m"  # kraft tan
    CL = "\033[38;2;217;119;87m"       # claude coral (model)
    EFFORT = "\033[38;2;156;142;126m"  # warm taupe

    parts = []

    # Context bar — bar + used percentage, whole number (e.g. [####---] 57%)
    if pct is not None:
        bar, color = format_bar(pct)
        parts.append(f"{bar} {color}{pct:.0f}%{R}")

    # Rate limits — compact [5h/7d%]
    rl5 = five_hour.get("used_percentage")
    rl7 = seven_day.get("used_percentage")
    if rl5 is not None:
        worst = max(rl5, rl7 or 0)
        if worst < 50:
            rl_color = GREEN
        elif worst < 80:
            rl_color = YELLOW
        else:
            rl_color = RED
        rl_text = f"{rl5:.0f}%/{rl7:.0f}%" if rl7 is not None else f"{rl5:.0f}%"
        parts.append(f"{rl_color}{rl_text}{R}")

    if folder:
        parts.append(f"{FOLDER}{folder}{R}")

    if branch:
        parts.append(f"{BRANCH}{branch}{R}")

    # Effort level (JSON field since v2.1.119); Opus 4.8 default=high, xhigh available
    effort = data.get("effort", {}).get("level")
    if effort:
        parts.append(f"{EFFORT}{effort}{R}")

    model = model.split(" (")[0]  # "Opus 4.8 (1M context)" → "Opus 4.8"
    parts.append(f"{CL}{model}{R}")

    print(SEP.join(parts))

if __name__ == "__main__":
    main()
