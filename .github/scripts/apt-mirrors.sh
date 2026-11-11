#!/bin/bash
# Drops apt mirrors whose host name doesn't resolve from the runner's mirror list, before `apt-get update`.
# On 2026-11-11 azure.archive.ubuntu.com, the first mirror in GitHub's ubuntu-24.04 images, didn't resolve for
# hours and apt didn't fall back to the next one: every package fetch failed with "Temporary failure resolving
# 'azure.archive.ubuntu.com'" and the jobs stopped before building. With it dropped, apt uses the list's other
# mirrors (archive.ubuntu.com). Nothing changes while every mirror resolves, or when the image has no such list.
list=/etc/apt/apt-mirrors.txt
[ -f "$list" ] || exit 0
for host in $(grep -o -E 'https?://[^/[:space:]]+' "$list" | sed -E 's#^https?://##' | sort -u); do
  if ! getent hosts "$host" > /dev/null; then
    echo "apt-mirrors: $host doesn't resolve; dropped from $list"
    sudo sed -i "\#://$host/#d" "$list"
  fi
done
if ! grep -q -E 'https?://' "$list"; then
  echo "apt-mirrors: no mirror in $list resolves; apt-get will fail"
fi
exit 0
