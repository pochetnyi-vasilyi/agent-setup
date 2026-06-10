#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
PreToolUse guard hook (Claude Code / Codex).

Structure-aware command analysis instead of raw substring matching:
the command line is stripped of heredoc bodies, split into shell segments
(respecting quotes, command substitution and pipes), each segment is
tokenized with shlex, and rules run against the actual command position
and its arguments. String literals, commit messages, grep patterns and
quoted ssh remote payloads no longer trigger false positives.

Verdict tiers:
  DENY  -> exit 2, message on stderr (hard block, fed back to the model)
  ASK   -> permissionDecision "ask" JSON (interactive approval;
           auto-denied in headless runs; mapped to DENY under Codex)
  ALLOW -> exit 0

Known, accepted limitations (availability over adversary-proofing):
  - quoted ssh/remote payloads are not analyzed (remote is user's domain)
  - heredoc bodies are dropped before analysis
  - an agent determined to bypass the hook can always write a script file;
    this hook protects against accidental footguns, not malice
"""

import json
import os
import re
import shlex
import sys
import platform
from datetime import datetime
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
SCRIPT_ROOT = Path(__file__).resolve().parents[1]
IS_CODEX = bool(os.environ.get('CODEX_HOME')) or SCRIPT_ROOT.name == '.codex'
HOME = str(Path.home())

ALLOW, ASK, DENY = 0, 1, 2

# ---------------------------------------------------------------------------
# shell parsing
# ---------------------------------------------------------------------------

HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def strip_heredocs(text: str) -> str:
    """Drop heredoc bodies so their content is not parsed as shell code."""
    out, delim, strip_tabs = [], None, False
    for line in text.split('\n'):
        if delim is not None:
            if line.rstrip() == delim or (strip_tabs and line.lstrip('\t').rstrip() == delim):
                delim = None
            continue
        m = HEREDOC_RE.search(line)
        out.append(line)
        if m:
            delim = m.group(2)
            strip_tabs = '<<-' in line
    return '\n'.join(out)


def split_segments(text: str) -> list[tuple[str, bool]]:
    """Split into simple-command segments. Returns [(segment, piped_from_prev)].

    Splits on  ; & && || | newline ( ) ` $(  outside quotes; single quotes are
    inert, command substitution opens even inside double quotes.
    """
    segs: list[tuple[str, bool]] = []
    cur: list[str] = []
    in_sq = in_dq = False
    piped = False
    i, n = 0, len(text)

    def flush(next_piped: bool):
        nonlocal cur, piped
        s = ''.join(cur).strip()
        if s:
            segs.append((s, piped))
        cur = []
        piped = next_piped

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if in_sq:
            cur.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if c == '\\':
            cur.append(c)
            if nxt:
                cur.append(nxt)
            i += 2
            continue
        if c == "'" and not in_dq:
            in_sq = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = not in_dq
            cur.append(c)
            i += 1
            continue
        if c == '`':
            flush(False)
            i += 1
            continue
        if c == '$' and nxt == '(':
            flush(False)
            i += 2
            continue
        if in_dq:
            cur.append(c)
            i += 1
            continue
        if c == '|':
            if nxt == '|':
                flush(False)
                i += 2
            else:
                flush(True)
                i += 1
            continue
        if c == '&':
            if nxt == '&':
                flush(False)
                i += 2
                continue
            if (cur and cur[-1] == '>') or nxt in '><0123456789':
                cur.append(c)
                i += 1
                continue
            flush(False)
            i += 1
            continue
        if c in ';\n()':
            flush(False)
            i += 1
            continue
        cur.append(c)
        i += 1
    flush(False)
    return segs


REDIR_OP_RE = re.compile(r'^\d*>>?$')
REDIR_INLINE_RE = re.compile(r'^(\d*>>?|&>>?)(.+)$')
REDIR_DUP_RE = re.compile(r'^\d*>&\d+-?$')


def extract_redirects(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Pull output-redirect targets out of the token list."""
    targets, out = [], []
    expect_target = False
    for t in tokens:
        if expect_target:
            targets.append(t)
            expect_target = False
            continue
        if REDIR_OP_RE.match(t) or t in ('&>', '&>>'):
            expect_target = True
            continue
        if REDIR_DUP_RE.match(t):
            continue
        m = REDIR_INLINE_RE.match(t)
        if m and not REDIR_DUP_RE.match(t):
            targets.append(m.group(2))
            continue
        if t.startswith('<'):
            continue  # input redirect / stripped heredoc marker
        out.append(t)
    return targets, out


ASSIGN_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')

WRAPPERS = {
    'sudo', 'doas', 'command', 'exec', 'nohup', 'nice', 'ionice',
    'stdbuf', 'timeout', 'time', 'watch', 'xargs', 'env', 'setsid',
}
WRAPPER_VALUE_FLAGS = {
    'sudo': {'-u', '-g', '-p', '-h'},
    'nice': {'-n'},
    'ionice': {'-c', '-n'},
    'timeout': {'-s', '-k', '--signal', '--kill-after'},
    'xargs': {'-I', '-d', '-n', '-P', '-L', '-a', '-E', '-s'},
    'env': {'-u', '-C', '-S'},
    'watch': {'-n', '-d'},
}


def resolve_command(tokens: list[str]) -> tuple[str | None, list[str]]:
    """Skip env assignments and wrapper commands; return (command, args)."""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if ASSIGN_RE.match(t):
            i += 1
            continue
        name = os.path.basename(t)
        if name in WRAPPERS:
            value_flags = WRAPPER_VALUE_FLAGS.get(name, set())
            i += 1
            while i < len(tokens):
                tk = tokens[i]
                if tk in value_flags:
                    i += 2
                    continue
                if tk.startswith('-'):
                    i += 1
                    continue
                break
            if name == 'timeout' and i < len(tokens):
                i += 1  # duration
            continue
        return name, tokens[i + 1:]
    return None, []


def expand_path(p: str) -> str:
    if p == '~':
        return HOME
    if p.startswith('~/'):
        return HOME + p[1:]
    return p.replace('${HOME}', HOME).replace('$HOME', HOME)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

SYSTEM_TOP = {
    'etc', 'usr', 'var', 'boot', 'bin', 'sbin', 'lib', 'lib64',
    'opt', 'srv', 'root', 'sys', 'proc', 'dev', 'run', 'nix',
}


def classify_rm_target(t: str) -> tuple[int, str | None]:
    if t in ('{}', '{}/'):
        return ALLOW, None
    p = expand_path(t)
    if p in ('.', './', '..', '../') or p.startswith('../'):
        return ASK, f'rm -r {t}: current/parent directory'
    if p == '*':
        return ASK, 'rm -r *: wildcard wipe of current directory'
    if not p.startswith('/'):
        return ALLOW, None
    base = p.rstrip('*').rstrip('/')
    if base == '':
        return DENY, f'rm -r {t}: filesystem root'
    if base == HOME or (HOME + '/').startswith(base + '/'):
        return DENY, f'rm -r {t}: home directory (or its parent)'
    if base.startswith(HOME + '/'):
        depth = base[len(HOME) + 1:].count('/')
        if depth == 0:
            return ASK, f'rm -r {t}: top-level directory in $HOME'
        return ALLOW, None
    parts = [x for x in base.split('/') if x]
    top = parts[0]
    if top == 'tmp' or base.startswith('/var/tmp') or base.startswith('/dev/shm'):
        return ALLOW, None
    if top == 'home':
        if len(parts) <= 2:
            return DENY, f'rm -r {t}: user home root'
        return ALLOW, None
    if top in ('mnt', 'media'):
        return ASK, f'rm -r {t}: mounted volume'
    if top in SYSTEM_TOP:
        return DENY, f'rm -r {t}: system path'
    if len(parts) == 1:
        return ASK, f'rm -r {t}: top-level directory'
    return ALLOW, None


def check_rm(args: list[str]) -> tuple[int, str | None]:
    recursive = False
    targets = []
    flags_done = False
    for a in args:
        if not flags_done and a == '--':
            flags_done = True
            continue
        if not flags_done and a.startswith('--'):
            if a == '--recursive':
                recursive = True
            continue
        if not flags_done and a.startswith('-') and len(a) > 1:
            if 'r' in a or 'R' in a:
                recursive = True
            continue
        targets.append(a)
    if not recursive:
        return ALLOW, None
    worst, reason = ALLOW, None
    for t in targets:
        v, r = classify_rm_target(t)
        if v > worst:
            worst, reason = v, r
    return worst, reason


def check_chmod(args: list[str]) -> tuple[int, str | None]:
    recursive = any(
        a in ('-R', '--recursive')
        or (a.startswith('-') and not a.startswith('--') and 'R' in a)
        for a in args
    )
    positional = [a for a in args if not a.startswith('-')]
    if not positional or positional[0] not in ('777', '0777', 'a+rwx', 'ugo+rwx'):
        return ALLOW, None
    if recursive:
        return DENY, 'recursive chmod 777'
    for t in positional[1:]:
        p = expand_path(t)
        if p.startswith('/'):
            parts = [x for x in p.split('/') if x]
            if len(parts) <= 2 or parts[0] in SYSTEM_TOP:
                return DENY, f'chmod 777 on system path {t}'
    return ALLOW, None


def check_git(args: list[str]) -> tuple[int, str | None]:
    i = 0
    while i < len(args) and args[i].startswith('-'):
        i += 2 if args[i] in ('-C', '-c') else 1
    if i >= len(args):
        return ALLOW, None
    sub, rest = args[i], args[i + 1:]
    if sub == 'push':
        if any(a == '--force-with-lease' or a.startswith('--force-with-lease=')
               or a == '--force-if-includes' for a in rest):
            return ALLOW, None
        if '--force' in rest or '-f' in rest or any(re.match(r'^\+\w', a) for a in rest):
            return ASK, 'git push --force: rewrites remote history'
        if '--delete' in rest or '-d' in rest:
            return ASK, 'git push --delete: removes a remote branch'
        if '--mirror' in rest:
            return ASK, 'git push --mirror: overwrites all remote refs'
    elif sub == 'reset' and '--hard' in rest:
        return ASK, 'git reset --hard: discards uncommitted changes'
    elif sub == 'clean':
        for a in rest:
            if a == '--force' or (a.startswith('-') and not a.startswith('--') and 'f' in a):
                return ASK, 'git clean -f: deletes untracked files'
    return ALLOW, None


def check_gh(args: list[str]) -> tuple[int, str | None]:
    positional = [a for a in args if not a.startswith('-')]
    if positional[:2] == ['repo', 'delete']:
        return DENY, 'gh repo delete: irreversible remote deletion'
    if positional[:2] == ['release', 'delete']:
        return ASK, 'gh release delete: removes a published release'
    return ALLOW, None


def check_docker(args: list[str]) -> tuple[int, str | None]:
    positional = [a for a in args if not a.startswith('-')]
    if positional[:2] == ['system', 'prune'] and ('-a' in args or '--all' in args):
        return ASK, 'docker system prune -a: removes all unused images/volumes'
    is_run = positional[:1] == ['run'] or positional[:2] == ['container', 'run']
    if not is_run:
        return ALLOW, None
    for j, a in enumerate(args):
        val = None
        if a in ('-v', '--volume') and j + 1 < len(args):
            val = args[j + 1]
        elif a.startswith('--volume='):
            val = a.split('=', 1)[1]
        if val and (val == '/' or val.startswith('/:')):
            return DENY, 'docker run mounting / into a container'
    if '--privileged' in args:
        return ASK, 'docker run --privileged'
    if '--pid=host' in args or any(args[j:j + 2] == ['--pid', 'host'] for j in range(len(args))):
        return ASK, 'docker run --pid=host'
    return ALLOW, None


SSH_SAFE_BASENAMES = {
    'config', 'known_hosts', 'known_hosts.old',
    'authorized_keys', 'authorized_keys2', 'environment',
}


def classify_credential_path(path: str) -> str | None:
    """Return a description if path points at secret material, else None."""
    if not path:
        return None
    p = expand_path(path)
    m = re.search(r'(?:^|[/\\])\.ssh[/\\](.+)$', p)
    if m:
        base = re.split(r'[/\\]', m.group(1))[-1]
        if base in SSH_SAFE_BASENAMES or base.endswith('.pub') or base == '':
            return None
        return 'SSH private key material'
    if re.search(r'\.aws[/\\]credentials$', p):
        return 'AWS credentials'
    if re.search(r'\.kube[/\\]config$', p):
        return 'Kubernetes credentials'
    if re.search(r'gcloud[/\\](credentials|legacy_credentials|access_tokens)', p):
        return 'GCloud credentials'
    if re.search(r'\.gnupg[/\\](private-keys|secring)', p):
        return 'GPG private keys'
    base = re.split(r'[/\\]', p)[-1]
    if base in ('credentials.json', 'token.json', '.netrc', '_netrc', '.pgpass'):
        return f'credential file {base}'
    if re.search(r'\.(pem|key|p12|pfx)$', base):
        return 'private key / certificate file'
    return None


READERS = {
    'cat', 'head', 'tail', 'less', 'more', 'bat', 'batcat', 'strings',
    'xxd', 'od', 'hexdump', 'base64', 'grep', 'egrep', 'fgrep', 'rg',
    'awk', 'gawk', 'sed', 'cut', 'tac', 'nl', 'type', 'get-content', 'gc',
}
PATTERN_FIRST = {'grep', 'egrep', 'fgrep', 'rg', 'awk', 'gawk', 'sed'}
COPIERS = {'cp', 'scp', 'rsync', 'mv', 'install'}


def check_credential_access(cmd: str, args: list[str]) -> tuple[int, str | None]:
    skip_first = cmd in PATTERN_FIRST
    for a in args:
        if a.startswith('-'):
            continue
        if skip_first:
            skip_first = False
            continue
        hit = classify_credential_path(a)
        if hit:
            if cmd in READERS:
                return DENY, f'Reading {hit}: {a}'
            return ASK, f'Copying/moving {hit}: {a}'
    return ALLOW, None


def check_write_path(path: str) -> tuple[int, str | None]:
    if not path:
        return ALLOW, None
    p = expand_path(path)
    if re.search(r'(?:^|[/\\])\.ssh[/\\]', p):
        return ASK, f'writing into ~/.ssh: {path}'
    for root in (HOME + '/.claude', HOME + '/.claude-personal'):
        if p.startswith(root + '/hooks/') or p in (root + '/settings.json',
                                                   root + '/settings.local.json'):
            return ASK, 'modifying the guard hook or Claude settings'
    if p.startswith('/etc/'):
        return ASK, f'writing to system config: {path}'
    hit = classify_credential_path(p)
    if hit:
        return ASK, f'writing to {hit}: {path}'
    return ALLOW, None


SHELLS = {'sh', 'bash', 'zsh', 'dash', 'ksh'}
DOWNLOADERS = {'curl', 'wget'}
PYTHON_RE = re.compile(r'^python[\d.]*$')


def shell_execs_stdin(args: list[str]) -> bool:
    if '-c' in args:
        return False
    for a in args:
        if a in ('-s', '-'):
            return True
        if not a.startswith('-'):
            return False  # script file argument
    return True


def python_execs_stdin(args: list[str]) -> bool:
    if '-c' in args or '-m' in args:
        return False
    for a in args:
        if a == '-':
            return True
        if not a.startswith('-'):
            return False
    return True


def check_command(cmd: str, args: list[str]) -> tuple[int, str | None]:
    if cmd == 'rm':
        return check_rm(args)
    if cmd in ('shutdown', 'poweroff', 'halt', 'telinit', 'reboot'):
        return DENY, f'{cmd}: system power command'
    if cmd == 'init' and args and args[0] in ('0', '6'):
        return DENY, 'init 0/6: system halt/reboot'
    if cmd == 'systemctl':
        sub = next((a for a in args if not a.startswith('-')), '')
        if sub in ('poweroff', 'reboot', 'halt', 'kexec'):
            return DENY, f'systemctl {sub}'
    if cmd.startswith('mkfs'):
        return DENY, 'filesystem formatting'
    if cmd in ('fdisk', 'sfdisk', 'cfdisk', 'parted', 'wipefs'):
        if '-l' in args or '--list' in args:
            return ALLOW, None
        return DENY, f'{cmd}: disk partitioning'
    if cmd == 'dd':
        for a in args:
            if re.match(r'^of=/dev/(sd|hd|vd|nvme|mmcblk|md|dm-|disk)', a):
                return DENY, 'dd: direct write to a block device'
        return ALLOW, None
    if cmd == 'chmod':
        return check_chmod(args)
    if cmd == 'git':
        return check_git(args)
    if cmd == 'gh':
        return check_gh(args)
    if cmd == 'docker':
        return check_docker(args)
    if cmd in ('nc', 'ncat', 'netcat') and '-e' in args:
        return DENY, f'{cmd} -e: reverse shell'
    if cmd in READERS or cmd in COPIERS:
        return check_credential_access(cmd, args)
    return ALLOW, None


# Severe patterns checked on raw text (whole command / unparseable fragments).
RAW_DENY = [
    (r':\(\)\s*\{', 'fork bomb'),
    (r'\bbash\s+-i\s+>&\s*/dev/tcp/', 'reverse shell'),
]

SEVERE_FALLBACK = [
    (r'\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(--\S+\s+)*["\']?(/|/\*|~|\$HOME)["\']?\s*($|[;&|])',
     'rm -rf on root/home'),
    (r'\bmkfs\.', 'filesystem formatting'),
    (r'\bdd\s+[^|;]*of=/dev/(sd|hd|vd|nvme|mmcblk)', 'direct disk write'),
    (r':\(\)\s*\{', 'fork bomb'),
]


def severe_fallback(text: str) -> tuple[int, str | None]:
    for pat, why in SEVERE_FALLBACK:
        if re.search(pat, text):
            return DENY, why
    return ALLOW, None


# Legacy Windows checks (raw patterns; only run when actually on Windows).
WINDOWS_RAW = [
    (r'\b(del|erase)\s+/[sfq].*[a-z]:\\', 'recursive delete on drive root'),
    (r'\b(rd|rmdir)\s+/[sq].*[a-z]:\\', 'recursive delete on drive root'),
    (r'remove-item\s+.*-recurse.*(\$env:|[a-z]:\\(windows|users|program))', 'recursive delete on system path'),
    (r'\bformat\s+[a-z]:', 'disk format'),
    (r'\bdiskpart\b', 'disk partitioning'),
    (r'\bbcdedit\b|\bbcdboot\b', 'boot configuration'),
    (r'\breg\s+delete\s+hk', 'registry delete'),
    (r'\bnet\s+user\s+.*\s+/delete', 'user delete'),
    (r'iex\s*\(.*downloadstring', 'PowerShell download & execute'),
    (r'powershell\s+.*-enc\b', 'encoded PowerShell command'),
    (r'\bshutdown\s+/[srt]', 'system shutdown'),
    (r'stop-computer|restart-computer', 'PowerShell shutdown/restart'),
    (r'\bsc\s+delete\b', 'service delete'),
]


def check_windows_raw(text: str) -> tuple[int, str | None]:
    low = ' '.join(text.lower().split())
    for pat, why in WINDOWS_RAW:
        if re.search(pat, low):
            return DENY, why
    return ALLOW, None


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

def evaluate_bash(command: str, depth: int = 0) -> tuple[int, str | None]:
    if not command or depth > 3:
        return ALLOW, None
    text = strip_heredocs(command)

    if IS_WINDOWS:
        v, r = check_windows_raw(text)
        if v != ALLOW:
            return v, r

    for pat, why in RAW_DENY:
        if re.search(pat, text):
            return DENY, why

    worst, reason = ALLOW, None

    def bump(v, r):
        nonlocal worst, reason
        if v > worst:
            worst, reason = v, r

    downloader_in_pipe = False
    for seg_text, piped in split_segments(text):
        if not piped:
            downloader_in_pipe = False
        try:
            tokens = shlex.split(seg_text)
        except ValueError:
            bump(*severe_fallback(seg_text))
            continue
        redirect_targets, tokens = extract_redirects(tokens)
        cmd, args = resolve_command(tokens)

        for tgt in redirect_targets:
            if re.match(r'^/dev/(sd|hd|vd|nvme|mmcblk)', tgt):
                return DENY, 'write to a raw block device'
            bump(*check_write_path(tgt))

        if not cmd:
            continue

        # inline code: bash -c '...' / eval '...'
        if cmd in SHELLS and '-c' in args:
            idx = args.index('-c')
            if idx + 1 < len(args):
                bump(*evaluate_bash(args[idx + 1], depth + 1))
        elif cmd == 'eval' and args:
            bump(*evaluate_bash(' '.join(args), depth + 1))

        # pipeline: remote content into an interpreter's stdin
        if cmd in DOWNLOADERS:
            downloader_in_pipe = True
        elif piped and downloader_in_pipe:
            if cmd in SHELLS and shell_execs_stdin(args):
                bump(ASK, f'remote script piped into {cmd} — verify the source URL')
            elif PYTHON_RE.match(cmd) and python_execs_stdin(args):
                bump(ASK, 'remote content piped into python stdin — verify the source URL')

        bump(*check_command(cmd, args))
        if worst == DENY:
            return DENY, reason

    return worst, reason


def evaluate(tool_name: str, tool_input: dict) -> tuple[int, str | None]:
    if not isinstance(tool_input, dict):
        return ALLOW, None
    if tool_name == 'Bash':
        return evaluate_bash(tool_input.get('command', ''))
    if tool_name == 'Read':
        hit = classify_credential_path(tool_input.get('file_path', ''))
        if hit:
            return DENY, f'Reading {hit}: {tool_input.get("file_path", "")}'
        return ALLOW, None
    if tool_name in ('Edit', 'Write', 'MultiEdit', 'NotebookEdit'):
        path = tool_input.get('file_path', '') or tool_input.get('notebook_path', '')
        return check_write_path(path)
    return ALLOW, None


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

def resolve_log_dir() -> Path:
    candidates = []
    codex_home = os.environ.get('CODEX_HOME')
    if codex_home:
        candidates.append(Path(codex_home) / 'logs')
    if SCRIPT_ROOT.name == '.codex':
        candidates.append(SCRIPT_ROOT / 'log')
    config_dir = os.environ.get('CLAUDE_CONFIG_DIR')
    if config_dir:
        candidates.append(Path(config_dir) / 'logs')
    candidates.append(Path.home() / '.claude' / 'logs')
    candidates.append(Path('/tmp'))
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            if os.access(candidate, os.W_OK):
                return candidate
        except OSError:
            continue
    return Path('/tmp')


def log_action(log_dir: Path, tool_name: str, tool_input: dict, decision: str, reason: str | None):
    path = log_dir / 'pre_tool_use.jsonl'
    try:
        if path.exists() and path.stat().st_size > 5_000_000:
            path.replace(path.with_suffix('.jsonl.old'))
    except OSError:
        pass
    summary = ''
    if isinstance(tool_input, dict):
        summary = tool_input.get('command') or tool_input.get('file_path') or ''
    entry = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'tool_name': tool_name,
        'decision': decision,
        'reason': reason,
        'input': str(summary)[:500],
    }
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        pass


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f'guard.py: invalid stdin JSON: {e}', file=sys.stderr)
        sys.exit(2)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {}) or {}
    log_dir = resolve_log_dir()

    try:
        verdict, reason = evaluate(tool_name, tool_input)
    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        command = tool_input.get('command', '') if isinstance(tool_input, dict) else ''
        verdict, reason = severe_fallback(command)
        if verdict == ALLOW:
            print(f'guard.py: internal error ({type(e).__name__}), '
                  f'severe-pattern fallback passed', file=sys.stderr)

    if verdict == ASK and IS_CODEX:
        verdict = DENY
        reason = f'{reason} (requires interactive approval, unavailable under Codex)'

    decision = {ALLOW: 'allow', ASK: 'ask', DENY: 'deny'}[verdict]
    log_action(log_dir, tool_name, tool_input, decision, reason)

    if verdict == DENY:
        print(f'BLOCKED: {reason}', file=sys.stderr)
        sys.exit(2)
    if verdict == ASK:
        print(json.dumps({
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': 'ask',
                'permissionDecisionReason': reason,
            }
        }))
    sys.exit(0)


if __name__ == '__main__':
    main()
