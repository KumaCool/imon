#!/bin/sh
set -eu

case "$(cat /proc/1/comm)" in systemd) ;; *) exit 1 ;; esac
count=0
until test -S /run/systemd/private && systemctl start dbus; do
  count=$((count + 1))
  [ "$count" -lt 20 ] || exit 1
  sleep 1
done
for account in fixture_reader fixture_operator; do
  useradd -m -s /usr/bin/fish "$account"
  ssh-keygen -q -t ed25519 -N '' -f "/tmp/$account"
  install -d -m 0700 -o "$account" "/home/$account/.ssh"
  install -m 0600 -o "$account" "/tmp/$account.pub" "/home/$account/.ssh/authorized_keys"
done
mkdir -p /run/sshd
ssh-keygen -A
for port in 22444 22445; do
  set --
  if [ "$port" = 22444 ]; then set -- -o 'Subsystem=sftp internal-sftp'; fi
  /usr/sbin/sshd -f /dev/null -o AddressFamily=inet -o ListenAddress=127.0.0.1 -o "Port=$port" \
    -o HostKey=/etc/ssh/ssh_host_ed25519_key -o PasswordAuthentication=no -o PermitRootLogin=no \
    -o UsePAM=yes -o "PidFile=/run/sshd-$port.pid" "$@"
done
cat >/etc/systemd/system/imon-fixture.service <<'UNIT'
[Unit]
Description=Disposable Imon smoke test
[Service]
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
UNIT
printf '%s\n' \
  'fixture_operator ALL=(root) NOPASSWD: /usr/bin/systemctl stop -- imon-fixture.service, /usr/bin/systemctl start -- imon-fixture.service' \
  'fixture_operator ALL=(root) NOPASSWD: /usr/bin/id -u, /bin/sh' >/etc/sudoers.d/imon-fixture
chmod 0440 /etc/sudoers.d/imon-fixture
visudo -c -q
systemctl daemon-reload
systemctl enable --now imon-fixture.service >/dev/null
before=$(systemctl is-enabled imon-fixture.service)
[ "$before" = enabled ]

ufw --force enable >/dev/null
ufw allow 18721/tcp >/dev/null
nft add table inet monitor_fixture
nft add chain inet monitor_fixture sample
nft add rule inet monitor_fixture sample tcp dport 18722 accept
iptables-legacy -A INPUT -p tcp --dport 18723 -j ACCEPT
ip6tables-legacy -A INPUT -p tcp --dport 18724 -j ACCEPT
rules() {
  ufw status verbose
  nft --stateless list ruleset
  iptables-legacy-save | sed '/^#/d;s/\[[0-9]*:[0-9]*\]/[0:0]/g'
  ip6tables-legacy-save | sed '/^#/d;s/\[[0-9]*:[0-9]*\]/[0:0]/g'
}
rules >/tmp/firewall-before
/fixture/host-smoke
rules >/tmp/firewall-after
cmp /tmp/firewall-before /tmp/firewall-after
after=$(systemctl is-enabled imon-fixture.service)
[ "$after" = "$before" ] && [ "$(systemctl is-active imon-fixture.service)" = active ]
printf 'Firewall rules unchanged; systemd enabled before=%s after=%s, final state=active\n' "$before" "$after"
