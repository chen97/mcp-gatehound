#!/bin/sh
# Design system v2.0 (CHE-1430): every one of Chen Hao's sites and apps wears the look that lives
# here, in chen97/todo: public/tokens.css (the tokens) and public/glass.css (the "Soft glass" layer).
# A repo copies this script once, to tools/sync-look.sh, and never edits it. The script copies the
# two files, unchanged, into one folder of that repo and records the commit in a SOURCE file. Never
# edit the copies by hand: change chen97/todo, then run this in each repo.
#
#   tools/sync-look.sh [dir]            copy from todo's main into dir (default public/look)
#   tools/sync-look.sh [dir] <ref>      copy from a branch, tag or commit
#   tools/sync-look.sh --check [dir]    exit 1 if the copy differs from todo's main
#
# A desktop app's web view passes its UI folder, e.g. `tools/sync-look.sh rust/ui/src/look`.
# Needs GITHUB_TOKEN (chen97/todo is private). Run from the repo root.
set -eu
check=0
[ "${1:-}" = "--check" ] && { check=1; shift; }
dir="${1:-public/look}"; ref="${2:-main}"
api=https://api.github.com/repos/chen97/todo
get() { curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: $2" "$api/$1"; }
sha=$(get "commits/$ref" application/vnd.github.sha)
if [ $check = 1 ]; then
  have=$(sed -n 's/^commit //p' "$dir/SOURCE" 2>/dev/null || true)
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  for f in tokens.css glass.css; do get "contents/public/$f?ref=$sha" application/vnd.github.raw > "$tmp/$f"; done
  if cmp -s "$tmp/tokens.css" "$dir/tokens.css" && cmp -s "$tmp/glass.css" "$dir/glass.css"; then
    echo "in step with todo $sha (copied from ${have:-?})"; exit 0
  fi
  echo "the look in chen97/todo has changed since ${have:-the last copy}: run tools/sync-look.sh $dir"; exit 1
fi
mkdir -p "$dir"
for f in tokens.css glass.css; do get "contents/public/$f?ref=$sha" application/vnd.github.raw > "$dir/$f"; done
printf 'Copied verbatim from chen97/todo by tools/sync-look.sh (design system v2.0). Do not edit.\ncommit %s\n' "$sha" > "$dir/SOURCE"
echo "copied tokens.css and glass.css from todo $sha into $dir"
