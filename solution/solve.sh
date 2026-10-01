#!/bin/sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 "$HERE/audit_core.py" --mode reference --output /app/audit.json
