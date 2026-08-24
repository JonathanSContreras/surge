#!/usr/bin/env bash
# Regenerate Surge-Runbook.pdf from RUNBOOK.md.
#   deps: brew install pandoc && pipx install weasyprint
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)

# Re-emit the title block as HTML so pandoc's own title header isn't used,
# and drop the markdown H1/intro that it replaces.
python3 - "$TMP" <<'PY'
import sys
tmp = sys.argv[1]
body = open("RUNBOOK.md").read().split("---\n", 1)[1]
head = ('<div class="titleblock">\n<h1>Surge</h1>\n'
        '<p class="subtitle">Operations Runbook</p>\n'
        '<p class="meta">Apple M2 Mac mini &middot; <code>hcucoses-Mac-mini</code>'
        ' &middot; code at <code>/opt/surge</code></p>\n</div>\n\n'
        'Written for an instructor, TA, or the next student, assuming no prior '
        'contact with the project. If you read only one section, read '
        '**Is it working?** and **When something is broken**.\n')
open(f"{tmp}/src.md", "w").write(head + body)
PY

pandoc "$TMP/src.md" -f gfm -t html5 -o "$TMP/frag.html"
{ printf '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
  printf '<title>Surge Operations Runbook</title></head><body>\n'
  cat "$TMP/frag.html"
  printf '\n</body></html>\n'; } > "$TMP/runbook.html"

weasyprint -s docs/runbook.css "$TMP/runbook.html" Surge-Runbook.pdf
rm -rf "$TMP"
echo "wrote Surge-Runbook.pdf"
