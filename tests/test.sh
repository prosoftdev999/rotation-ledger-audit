#!/bin/sh
set -eu
mkdir -p /logs/verifier
printf '0\n' > /logs/verifier/reward.txt
status=1
finish() {
  if [ "$status" -eq 0 ]; then printf '1\n' > /logs/verifier/reward.txt; else printf '0\n' > /logs/verifier/reward.txt; fi
}
trap finish EXIT HUP INT TERM
if pytest -q /tests/test_verify.py --ctrf=/logs/verifier/ctrf.json; then status=0; else status=$?; fi
exit "$status"
