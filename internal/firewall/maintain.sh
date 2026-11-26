#!/bin/sh
# Install or remove only this application's unprivileged read entry point.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
[ "$(id -u)" = 0 ] || exit 1
[ "$#" = 3 ] && [ "$2" = --collector ] || exit 2
action=$1
collector=$3
case "$action" in install|uninstall|verify) ;; *) exit 2 ;; esac
case "$collector" in ''|root|[!A-Za-z_]*|*[!A-Za-z0-9_.-]*) exit 2 ;; esac
[ "${#collector}" -le 64 ] && [ "$(id -u -- "$collector")" != 0 ] || exit 2
for tool in flock sha256sum stat mktemp visudo sudo install base64 runuser; do command -v "$tool" >/dev/null; done
validate_dir() {
  check_dir=$1
  while :; do
    [ -d "$check_dir" ] && [ ! -L "$check_dir" ] && [ "$(stat -c %u "$check_dir")" = 0 ] || return 1
    mode=$(stat -c %a "$check_dir")
    [ "$((0$mode & 022))" = 0 ] || return 1
    [ "$check_dir" != / ] || break
    check_dir=$(dirname -- "$check_dir")
  done
}
validate_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%h:%a' "$1")" = "0:1:$2" ]
}
checksum() { result=$(sha256sum -- "$1"); printf '%s\n' "${result%% *}"; }
present() { [ -e "$1" ] || [ -L "$1" ]; }
read_manifest() {
  validate_file "$manifest" 600
  record=$(cat -- "$manifest")
  read_hash=$(printf '%s\n' "$record" | sed -n 's/^.*"binary_sha256":"\([a-f0-9]*\)".*$/\1/p')
  [ "${#read_hash}" = 64 ]
  [ "$record" = "$(printf '{"version":1,"collector":"%s","binary_sha256":"%s"}' "$collector" "$read_hash")" ]
}
auth_entry() { printf '%s ALL=(root) NOPASSWD: NOSETENV: %s ""\n' "$collector" "$helper"; }
set_layout() {
  state=/var/lib/$1
  lib=/usr/local/libexec/$1
  helper=$lib/firewall-read
  sudoers=/etc/sudoers.d/$1-firewall
  auth_prefix=/etc/sudoers.d/.$1
  manifest=$state/firewall-manifest.json
  lock=$state/firewall.lock
}
assert_no_temporary_files() {
  for path in "$state"/.stage.???????? "$lib"/.reader.???????? "$auth_prefix".????????; do
    if present "$path"; then return 1; fi
  done
}
layout_present() {
  present "$manifest" || present "$sudoers" || present "$helper" || present "$lock"
}
validate_dir /var/lib
validate_dir /etc/sudoers.d
validate_dir /usr/local
# Lock the stable parent without leaving a new app-owned lock file.
exec 8</var/lib
flock -w 10 8
if present /usr/local/libexec; then validate_dir /usr/local/libexec; fi
# Fresh installations use Imon paths. Existing authorizations retain their
# validated layout until uninstalled, including when updating the reader.
installed_layout=
for layout in infra-monitor imon; do
  set_layout "$layout"
  for d in "$state" "$lib"; do
    if present "$d"; then validate_dir "$d"; fi
  done
  if present "$lock"; then
    validate_file "$lock" 600
    exec 9<"$lock"
    flock -w 10 9
  fi
  assert_no_temporary_files
  if layout_present; then
    [ -z "$installed_layout" ] || exit 1
    installed_layout=$layout
  fi
done
set_layout "${installed_layout:-imon}"
verify_uninstalled() {
  ! present "$manifest" && ! present "$sudoers" && ! present "$helper" && ! present "$lock" || return 1
  assert_no_temporary_files
  printf '%s\n' uninstalled
}
verify_installed() {
  read_manifest
  validate_file "$helper" 755
  [ "$(checksum "$helper")" = "$read_hash" ]
  validate_file "$sudoers" 440
  auth_entry | cmp -s -- "$sudoers" -
  visudo -c -q
  printf 'installed %s\n' "$read_hash"
}
if [ "$action" = verify ]; then
  if ! present "$manifest" && ! present "$sudoers" && ! present "$helper"; then
    verify_uninstalled
  else
    verify_installed
  fi
  exit 0
fi
remove_empty_dirs() {
  if present "$lib"; then rmdir -- "$lib" 2>/dev/null || :; fi
  if present "$state"; then rmdir -- "$state" 2>/dev/null || :; fi
}
if [ "$action" = uninstall ] && ! present "$manifest" && ! present "$sudoers" && ! present "$helper"; then
  rm -f -- "$lock"
  remove_empty_dirs
  verify_uninstalled
  exit 0
fi
for d in "$state" /usr/local/libexec "$lib"; do
  if ! [ -e "$d" ] && ! [ -L "$d" ]; then mkdir -m 0755 -- "$d"; fi
  validate_dir "$d"
done
visudo -c -q
stage=$(mktemp -d "$state/.stage.XXXXXXXX")
helper_tmp=$(mktemp "$lib/.reader.XXXXXXXX")
auth_tmp=$(mktemp "$auth_prefix.XXXXXXXX")
active=0
prior=0
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$active" = 1 ]; then
    rm -f -- "$sudoers"
    if [ "$prior" = 1 ]; then
      if [ -f "$stage/old-helper" ]; then install -m 0755 -- "$stage/old-helper" "$helper_tmp" && mv -f -- "$helper_tmp" "$helper" || status=1; fi
      mv -f -- "$stage/old-manifest" "$manifest" || status=1
      if [ -f "$stage/old-auth" ]; then install -m 0440 -- "$stage/old-auth" "$auth_tmp" && mv -f -- "$auth_tmp" "$sudoers" || status=1; fi
    else
      rm -f -- "$helper" "$manifest" || status=1
    fi
  fi
  rm -f -- "$helper_tmp" "$auth_tmp"
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
auth_entry > "$stage/expected-auth"
if [ -e "$manifest" ] || [ -L "$manifest" ]; then
  read_manifest
  if [ -e "$helper" ] || [ -L "$helper" ]; then
    validate_file "$helper" 755
    [ "$(checksum "$helper")" = "$read_hash" ]
  elif [ "$action" != uninstall ] || [ -e "$sudoers" ] || [ -L "$sudoers" ]; then
    exit 1
  fi
  if [ -e "$sudoers" ] || [ -L "$sudoers" ]; then
    validate_file "$sudoers" 440
    cmp -s -- "$sudoers" "$stage/expected-auth"
    cp -- "$sudoers" "$stage/old-auth"
  fi
  if [ -e "$helper" ]; then cp -- "$helper" "$stage/old-helper"; fi
  cp -- "$manifest" "$stage/old-manifest"
  prior=1
else
  [ ! -e "$helper" ] && [ ! -L "$helper" ] && [ ! -e "$sudoers" ] && [ ! -L "$sudoers" ]
fi
if [ "$action" = uninstall ]; then
  active=1
  rm -f -- "$sudoers"
  visudo -c -q
  rm -f -- "$helper" "$manifest"
  active=0
  rm -f -- "$lock" "$helper_tmp" "$auth_tmp"
  rm -rf -- "$stage"
  remove_empty_dirs
  verify_uninstalled
  exit 0
fi
wanted=@BINARY_SHA256@
base64 -d > "$stage/new-helper" <<'IMON_BINARY'
@FIREWALL_BINARY@
IMON_BINARY
[ "$(checksum "$stage/new-helper")" = "$wanted" ]
install -m 0755 -- "$stage/new-helper" "$helper_tmp"
install -m 0440 -- "$stage/expected-auth" "$auth_tmp"
visudo -c -q -f "$auth_tmp"
printf '{"version":1,"collector":"%s","binary_sha256":"%s"}\n' "$collector" "$wanted" > "$stage/new-manifest"
active=1
mv -f -- "$helper_tmp" "$helper"
mv -f -- "$stage/new-manifest" "$manifest"
mv -f -- "$auth_tmp" "$sudoers"
visudo -c -q
runuser -u "$collector" -- sudo -n -- "$helper" >/dev/null
verify_installed
active=0
