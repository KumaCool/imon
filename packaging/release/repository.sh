#!/bin/sh
set -eu

# Resolve the public GitHub Releases source without embedding a checkout URL or credentials.
src=$1
if [ "$#" -gt 1 ]; then
  repo=$2
elif [ "${IMON_RELEASE_REPO+x}" = x ]; then
  repo=$IMON_RELEASE_REPO
elif [ -n "${GITHUB_REPOSITORY:-}" ]; then
  repo=$GITHUB_REPOSITORY
else
  repo=''
  if prefix=$(git -C "$src" rev-parse --show-prefix 2>/dev/null) && [ -z "$prefix" ]; then
    remote=$(git -C "$src" config --get remote.origin.url 2>/dev/null || :)
    case "$remote" in
      https://github.com/*) repo=${remote#https://github.com/} ;;
      ssh://git@github.com/*) repo=${remote#ssh://git@github.com/} ;;
      git@github.com:*) repo=${remote#git@github.com:} ;;
    esac
    repo=${repo%.git}
  fi
fi
if [ -n "$repo" ]; then
  case "$repo" in */.|*/..|*[!a-zA-Z0-9_./-]*) repo='' ;; esac
  if ! printf '%s\n' "$repo" | LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9-]{0,39}/[A-Za-z0-9_.-]{1,100}$'; then
    printf 'GitHub release repository must be owner/repo.\n' >&2
    exit 2
  fi
fi
printf '%s\n' "$repo"
