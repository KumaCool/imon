#!/bin/sh
# Install or remove Imon's fixed privileged operations.
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
valid_digest() { [ "${#1}" = 64 ] && case "$1" in *[!a-f0-9]*) return 1 ;; esac; }
valid_release() { [ "${#1}" -le 33 ] && printf '%s\n' "$1" | grep -Eq '^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$'; }
read_manifest() {
  validate_file "$1" 600 || return 1
  record=$(cat -- "$1")
  read_hash=$(printf '%s\n' "$record" | sed -n 's/^.*"binary_sha256":"\([a-f0-9]*\)".*$/\1/p')
  valid_digest "$read_hash" || return 1
  read_release=
  read_key=
  if [ "$record" = "$(printf '{"version":1,"collector":"%s","binary_sha256":"%s"}' "$collector" "$read_hash")" ]; then
    return 0
  fi
  read_release=$(printf '%s\n' "$record" | sed -n 's/^.*"release":"\([^"]*\)".*$/\1/p')
  read_key=$(printf '%s\n' "$record" | sed -n 's/^.*"update_key":"\([a-f0-9]*\)".*$/\1/p')
  valid_release "$read_release" && valid_digest "$read_key" || return 1
  [ "$record" = "$(printf '{"version":2,"collector":"%s","binary_sha256":"%s","release":"%s","update_key":"%s"}' "$collector" "$read_hash" "$read_release" "$read_key")" ]
}
legacy_auth_entry() { printf '%s ALL=(root) NOPASSWD: NOSETENV: %s ""\n' "$collector" "$helper"; }
restricted_auth_entry() {
  printf '%s ALL=(root) NOPASSWD: NOSETENV: %s "", %s ports, %s grants, %s service\n' "$collector" "$helper" "$helper" "$helper" "$helper"
}
auth_entry() {
  printf '%s ALL=(root) NOPASSWD: NOSETENV: %s "", %s ports, %s service' "$collector" "$helper" "$helper" "$helper"
  if [ -n "$1" ]; then printf ', %s version, %s update' "$helper" "$helper"; fi
  if [ "$2" = removable ]; then printf ', %s uninstall' "$helper"; fi
  printf '\n'
}
verify_auth() {
  auth_entry "$read_key" removable | cmp -s -- "$1" - ||
    auth_entry "$read_key" legacy | cmp -s -- "$1" - ||
    { [ -z "$read_key" ] &&
      { restricted_auth_entry | cmp -s -- "$1" - ||
        legacy_auth_entry | cmp -s -- "$1" -; }; }
}
set_layout() {
  state=/var/lib/$1
  lib=/usr/local/libexec/$1
  helper=$lib/firewall-read
  sudoers=/etc/sudoers.d/$1-firewall
  auth_prefix=/etc/sudoers.d/.$1
  manifest=$state/firewall-manifest.json
  next_manifest=$state/.helper-next.json
  staging_manifest=$state/.helper-next.json.tmp
  next_helper=$lib/.helper-next
  units=$state/service-units
  lock=$state/firewall.lock
}
assert_no_temporary_files() {
  for path in "$state"/.stage.???????? "$lib"/.reader.???????? "$auth_prefix".????????; do
    if present "$path"; then return 1; fi
  done
}
layout_present() {
  present "$manifest" || present "$sudoers" || present "$helper" || present "$lock" || present "$units" ||
    present "$next_helper" || present "$next_manifest" || present "$staging_manifest"
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
recover_update() {
  if present "$next_manifest"; then
    read_manifest "$manifest"
    [ -n "$read_key" ]
    installed_hash=$read_hash
    installed_key=$read_key
    read_manifest "$next_manifest"
    [ "$read_key" = "$installed_key" ] && [ "$read_hash" != "$installed_hash" ] || return 1
    validate_file "$helper" 755
    active_hash=$(checksum "$helper")
    if [ "$active_hash" = "$installed_hash" ]; then
      rm -- "$next_manifest"
    elif [ "$active_hash" = "$read_hash" ]; then
      sync -f -- "$helper"
      mv -f -- "$next_manifest" "$manifest"
    else
      return 1
    fi
  fi
  if present "$next_helper"; then
    validate_file "$next_helper" 755 || validate_file "$next_helper" 600
    rm -- "$next_helper"
  fi
  if present "$staging_manifest"; then
    validate_file "$staging_manifest" 600
    rm -- "$staging_manifest"
  fi
}
recover_update
verify_uninstalled() {
  ! present "$manifest" && ! present "$sudoers" && ! present "$helper" && ! present "$lock" && ! present "$units" || return 1
  assert_no_temporary_files
  printf '%s\n' uninstalled
}
verify_installed() {
  read_manifest "$manifest"
  validate_file "$helper" 755
  [ "$(checksum "$helper")" = "$read_hash" ]
  validate_file "$sudoers" 440
  verify_auth "$sudoers"
  if present "$units"; then validate_file "$units" 600; fi
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
if [ "$action" = uninstall ] && ! present "$manifest" && ! present "$sudoers" && ! present "$helper" && ! present "$units"; then
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
    if [ -f "$stage/old-units" ]; then
      mv -f -- "$stage/old-units" "$units" || status=1
    else
      rm -f -- "$units" || status=1
    fi
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
if present "$units"; then
  validate_file "$units" 600
  cp -p -- "$units" "$stage/old-units"
fi
if [ -e "$manifest" ] || [ -L "$manifest" ]; then
  read_manifest "$manifest"
  if [ -e "$helper" ] || [ -L "$helper" ]; then
    validate_file "$helper" 755
    [ "$(checksum "$helper")" = "$read_hash" ]
  elif [ "$action" != uninstall ] || [ -e "$sudoers" ] || [ -L "$sudoers" ]; then
    exit 1
  fi
  if [ -e "$sudoers" ] || [ -L "$sudoers" ]; then
    validate_file "$sudoers" 440
    verify_auth "$sudoers"
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
  rm -f -- "$helper" "$manifest" "$units"
  active=0
  rm -f -- "$lock" "$helper_tmp" "$auth_tmp"
  rm -rf -- "$stage"
  remove_empty_dirs
  verify_uninstalled
  exit 0
fi
wanted_release='@HELPER_RELEASE@'
wanted_key='@HELPER_UPDATE_KEY@'
if [ -n "$wanted_release" ] || [ -n "$wanted_key" ]; then
  valid_release "$wanted_release"
  valid_digest "$wanted_key"
fi
auth_entry "$wanted_key" removable > "$stage/expected-auth"
wanted=@BINARY_SHA256@
base64 -d > "$stage/new-helper" <<'IMON_BINARY'
@FIREWALL_BINARY@
IMON_BINARY
[ "$(checksum "$stage/new-helper")" = "$wanted" ]
install -m 0755 -- "$stage/new-helper" "$helper_tmp"
install -m 0440 -- "$stage/expected-auth" "$auth_tmp"
visudo -c -q -f "$auth_tmp"
if [ -n "$wanted_key" ]; then
  printf '{"version":2,"collector":"%s","binary_sha256":"%s","release":"%s","update_key":"%s"}\n' \
    "$collector" "$wanted" "$wanted_release" "$wanted_key" > "$stage/new-manifest"
else
  printf '{"version":1,"collector":"%s","binary_sha256":"%s"}\n' "$collector" "$wanted" > "$stage/new-manifest"
fi
active=1
mv -f -- "$helper_tmp" "$helper"
mv -f -- "$stage/new-manifest" "$manifest"
rm -f -- "$units"
mv -f -- "$auth_tmp" "$sudoers"
visudo -c -q
runuser -u "$collector" -- sudo -n -- "$helper" >/dev/null
runuser -u "$collector" -- sudo -n -l -- "$helper" ports >/dev/null
runuser -u "$collector" -- sudo -n -l -- "$helper" service >/dev/null
runuser -u "$collector" -- sudo -n -l -- "$helper" uninstall >/dev/null
if [ -n "$wanted_key" ]; then
  runuser -u "$collector" -- sudo -n -l -- "$helper" version >/dev/null
  # Listing a sudo rule does not prove it can run without a password.
  # An empty update must reach the signed helper and be rejected before locking.
  update_status=0
  runuser -u "$collector" -- sudo -n -- "$helper" update </dev/null >/dev/null || update_status=$?
  if [ "$update_status" -ne 2 ]; then
    printf '%s\n' 'Imon helper update failed its non-interactive sudo check.' >&2
    exit 1
  fi
fi
verify_installed
active=0
