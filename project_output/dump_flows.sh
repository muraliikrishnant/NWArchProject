#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <before|after>"
  exit 1
fi

label="$1"
if [[ "$label" != "before" && "$label" != "after" ]]; then
  echo "label must be before or after"
  exit 1
fi

out_dir="${PROJECT_OUTPUT_DIR:-$HOME/project_output}"
mkdir -p "$out_dir"
timestamp="$(date +%Y%m%d_%H%M%S)"
outfile="$out_dir/flows_${label}_${timestamp}.txt"
stablefile="$out_dir/flows_${label}.txt"
runner=()
if command -v sudo >/dev/null 2>&1; then
  runner=(sudo)
fi

echo "# Flow dump: $label"
echo "# File: $outfile"

"${runner[@]}" ovs-ofctl -O OpenFlow10 dump-flows s1 | tee "$outfile" > "$stablefile"

echo "# Stable copy: $stablefile"

echo
echo "# Pretty view"
awk '
  /priority=/ {
    print "- " $0
    if ($0 ~ /dl_dst=/) {
      print "  note: destination MAC rule present"
    }
    if ($0 ~ /arp/) {
      print "  note: ARP-related entry present"
    }
  }
' "$outfile"

echo
echo "# Suspicious duplicates"
grep -o 'dl_dst=[^ ,]*' "$outfile" | sort | uniq -d | sed 's/^/- duplicate /' || true
