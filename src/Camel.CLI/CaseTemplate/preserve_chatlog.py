#!/usr/bin/env python3
"""Preserve the Claude Code client chat transcript into the case audit trail.

Wired by the case `.claude/settings.json` as a Claude Code `SessionEnd` hook. Claude Code writes the
full client-side conversation — every user/assistant message, tool call, and timestamp — to a JSONL
transcript under ~/.claude/projects/. This hook copies that transcript into the case's audit folder
(<case>/analysis/chatlogs/) so the chat log is bundled alongside Camel's per-case tool-execution audit
log (audit-<caseId>.clef) as one self-contained chain-of-custody record.

Hooks run via the harness, not as agent tool calls, so this works even though the agent's `Bash` tool
is denied by policy. The hook JSON payload is read from stdin; the key field is `transcript_path`.
The destination is anchored to $CLAUDE_PROJECT_DIR (the case root Claude Code exports to hooks).
"""
import datetime
import json
import os
import shutil
import sys


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception as e:  # malformed/empty stdin — nothing to do
        print(f"[preserve_chatlog] No hook payload on stdin: {e}", file=sys.stderr)
        return

    src = payload.get("transcript_path")
    if not src or not os.path.exists(src):
        print(f"[preserve_chatlog] transcript_path missing or not found: {src!r}", file=sys.stderr)
        return

    base = os.environ.get("CLAUDE_PROJECT_DIR") or "."
    dst_dir = os.path.join(base, "analysis", "chatlogs")
    os.makedirs(dst_dir, exist_ok=True)

    session_id = str(payload.get("session_id", "session"))
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = os.path.join(dst_dir, f"chatlog-{session_id}-{ts}.jsonl")

    try:
        shutil.copy2(src, dst)
        print(f"[preserve_chatlog] Preserved client chat log -> {dst}")
    except Exception as e:
        print(f"[preserve_chatlog] Failed to preserve chat log: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
