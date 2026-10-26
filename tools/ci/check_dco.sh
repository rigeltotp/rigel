#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Checks that every non-merge commit in BASE..HEAD carries a DCO sign-off
# ("Signed-off-by: Name <email>") matching its author (CONTRIBUTING.md).
# Usage: tools/ci/check_dco.sh BASE HEAD
set -euo pipefail

base="$1"
head="$2"
status=0
count=0

for commit in $(git rev-list --no-merges "$base..$head"); do
  count=$((count + 1))
  author="$(git log -1 --format='%an <%ae>' "$commit")"
  if git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" | grep -Fxq "$author"; then
    echo "ok   $(git log -1 --format='%h %s' "$commit")"
  else
    echo "FAIL $(git log -1 --format='%h %s' "$commit"): no 'Signed-off-by: $author'"
    status=1
  fi
done

echo "$count commit(s) checked."
if [ "$status" -ne 0 ]; then
  echo "Add the sign-off with: git rebase --signoff $base && git push --force-with-lease"
fi
exit "$status"
