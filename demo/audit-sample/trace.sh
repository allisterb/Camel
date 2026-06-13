#!/usr/bin/env bash
# Trace an agent finding back to the exact tool executions that produced it.
#
# Every Camel Execute result ends with an audit handle the agent cites in its report:
#     [audit] case=<caseId> execution=<id>
# Give this script that execution id and it prints the execution boundary plus every command that ran
# under it — with full attribution (workflow > toolkit/op > command line, host, exit code, duration) — from
# the per-case audit log alone. This is the "three-claim trace": finding -> execution id -> tool execution.
#
# Usage:  ./trace.sh <executionId> [caseId]
#   e.g.  ./trace.sh 7f3a9c21              # defaults to case srl-2018-rd01
#
# Requires jq (ships on the SIFT Workstation). For a no-jq box, see the grep one-liner in THREE_CLAIM_TRACE.md.
set -euo pipefail

inv="${1:?usage: ./trace.sh <executionId> [caseId]}"
case_id="${2:-srl-2018-rd01}"
file="$(dirname "$0")/audit-${case_id}.clef"
[ -f "$file" ] || { echo "audit file not found: $file" >&2; exit 1; }

echo "Case: ${case_id}   Execution: ${inv}   (${file})"
echo
jq -r --arg inv "$inv" '
  select(.ExecutionId == $inv)
  | if .EventType == "execution" then
      "• execution \(.Phase)  \(.["@t"])"
    elif .EventType == "command" then
      "• command  \(.["@t"])\n"
      + "    \(.Workflow // "—") › \(.WorkflowOperation // "—") › \(.Toolkit // "—")/\(.Operation // "—")\n"
      + "    $ \(.Command) \(.Arguments)\n"
      + "    host=\(.Host) exit=\(.ExitCode) \(.DurationMs)ms"
    else
      "• \(.EventType)"
    end
' "$file"
