#!/bin/bash

set -x

case $(uname -m) in
  aarch64 )
    arch=arm64
    ;;
  arm* )
    arch=armv7
    ;;
  * )
    arch=amd64
    ;;
esac

geturl=$(type -p curl &>/dev/null && echo "curl -sSLf" || echo "wget -O-")
checksum=$($geturl https://github.com/phuslu/liner/releases/download/v0.0.0/checksums.txt | grep -E "liner_linux_${arch}-[0-9]+.tar.gz")
filename=$(echo $checksum | awk '{print $2}')
pacfile=$(awk 'BEGIN{srand(); r=int(rand()*10000000000); printf "%06d.pac", r % 1000000}')
sudo=$(grep -q '^Uid:\s*0' /proc/self/status || echo sudo)
sha1sum=$(type -p sha1sum &>/dev/null && echo sha1sum || echo "openssl dgst -r -sha1")

if test -d liner; then
  cd liner
elif test -x liner; then
  true
else
  mkdir liner && cd liner
fi

if type -p curl; then
  curl -L https://github.com/phuslu/liner/releases/download/v0.0.0/$filename > $filename
else
  wget https://github.com/phuslu/liner/releases/download/v0.0.0/$filename -O $filename
fi

if test "$(cat $filename | $sha1sum | awk '{ print $1 }')" != "$(echo $checksum | awk '{print $1}')"; then
  echo "$filename sha1sum mismatched, please check your network!"
  rm -rf $filename
  exit 1
fi

if test -x liner; then
  echo liner | tar xvzf $filename -T -
  rm -rf $filename
  exit 0
fi

tar xvzf $filename
rm -rf $filename

domain=$($geturl whatismyip.akamai.com | tr . -).sslip.io

cat <<EOF > production.yaml
global:
  log_level: info
  max_idle_conns: 100
  dial_timeout: 30
  dns_cache_duration: 15m
https:
  - listen: [':443']
    server_name: ['${domain}']
    forward:
      log: true
      prefer_ipv6: false
      io_copy_buffer: 65536
      idle_timeout: 600
      auth_table: users.csv
      policy: |
        {{if eq "" .Request.UserAgent}}
          proxy_pass
        {{else if .Request.Header.Get "proxy-authorization"}}
          verify_auth
        {{else if all (.Request.ProtoAtLeast 2 0) (eq .Request.TLS.Version 0x0304) (greased .ClientHelloInfo)}}
          require_auth
        {{else}}
          proxy_pass
        {{end}}
    web:
      - location: /${pacfile}
        index:
          headers: "content-type: text/plain; charset=UTF-8"
          file: china.pac
      - location: /
        proxy:
          pass: 'http://127.0.0.1:80'
EOF

cat <<EOF > users.csv
username,password,speed_limit,allow_client
user,$(awk 'BEGIN{srand();for(i=0;i<3;i++)printf"%02x",rand()*256;print""}'),0,1
EOF

if test "$(cat /proc/1/comm)" == "systemd"; then
  cat <<EOF | ${sudo} tee /etc/systemd/system/liner@.service
[Unit]
Wants=network-online.target
After=network.target network-online.target local-fs.target
Description=a protocol liner

[Service]
Type=simple
KillMode=process
Restart=on-failure
WorkingDirectory=$(pwd)
ExecStartPre=-/bin/sh -c 'setcap "cap_net_bind_service,cap_setuid,cap_setgid=eip" liner'
ExecStart=$(pwd)/liner %i.yaml
User=${USER}
Group=${USER}
PermissionsStartOnly=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  ${sudo} systemctl enable --now liner@production.service
elif /sbin/rc-update -V; then
  ${sudo} rc-update add local
  echo 'while :; do "$@"; sleep 2; done' >keepalive
  printf '#!/bin/sh\n\n(cd "%s" && /bin/sh keepalive "%s/liner" production.yaml &) </dev/null &>/dev/null\n' "$(pwd)" "$(pwd)" | ${sudo} tee /etc/local.d/10-liner.start
  ${sudo} chmod +x /etc/local.d/10-liner.start
  ${sudo} /etc/local.d/10-liner.start
else
  kill -9 $(pidof liner) 2>/dev/null || true
  echo 'while :; do "$@"; sleep 2; done' >keepalive
  (/bin/sh keepalive $(pwd)/liner production.yaml &) </dev/null &>/dev/null
fi

echo "https://$domain/$pacfile"
cat users.csv
