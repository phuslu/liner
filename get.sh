#!/bin/bash

set -x

arch=amd64
case $(uname -m) in
  aarch64 )
    arch=arm64
    ;;
  arm* )
    arch=armv5
    if readelf -A /bin/sh | grep -q 'VFP registers'; then
      arch=armv7
    fi
    ;;
esac

if type -p curl; then
  getcurl="curl -sSLf"
else
  getcurl="wget -O-"
fi

checksum=$($getcurl https://github.com/phuslu/liner/releases/download/v0.0.0/checksums.txt | grep -E "liner_linux_${arch}-[0-9]+.tar.gz")
filename=$(echo $checksum | awk '{print $2}')
pacfile=$(head /dev/urandom | tr -dc '1-9' | head -c 6).pac

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

if test "$(sha1sum $filename)" != "$checksum"; then
  echo "$filename sha1sum mismatched, please check your network!"
  rm -rf $filename
  exit 1
fi

if [ -f production.yaml ] || [ -s .env ]; then
  echo liner | tar xvzf $filename -T -
  rm -rf $filename
  exit 0
fi

tar xvzf $filename
rm -rf $filename

domain=$($getcurl whatismyip.akamai.com | tr . -).sslip.io

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
      policy: |
        {{if all (.Request.ProtoAtLeast 2 0) (eq .Request.TLS.Version 0x0304) (greased .ClientHelloInfo)}}
            bypass_auth
        {{else}}
            proxy_pass
        {{end}}
    web:
      - location: /${pacfile}
        index:
          headers: "content-type: text/plain;charset=utf-8"
          file: $(pwd)/china.pac
      - location: /
        proxy:
          pass: 'http://127.0.0.1:80'
EOF

echo ENV=production > .env

if type -p systemctl; then
  cat <<EOF > liner.service
[Unit]
Wants=network-online.target
After=network.target network-online.target
Description=liner

[Service]
Type=simple
KillMode=process
Restart=on-failure
WorkingDirectory=$(pwd)
EnvironmentFile=-$(pwd)/.env
ExecStart=$(pwd)/liner \${ENV}.yaml
StandardError=append:$(pwd)/liner.error.log
User=${USER}
Group=${USER}
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl enable $(pwd)/liner.service
  sudo systemctl restart liner
elif type -p rc-update; then
  rc-update add local
  echo 'while :; do env $(cat .env) "$@"; sleep 2; done' >keepalive
  printf '#!/bin/sh\n\n(cd "%s" && /bin/sh keepalive "%s/liner" production.yaml &) </dev/null &>/dev/null\n' "$(pwd)" "$(pwd)" | tee /etc/local.d/10-liner.start
  chmod +x /etc/local.d/10-liner.start
  /etc/local.d/10-liner.start
else
  pgrep liner && pkill -9 liner
  echo 'while :; do env $(cat .env) "$@"; sleep 2; done' >keepalive
  (/bin/sh keepalive $(pwd)/liner production.yaml &) </dev/null &>/dev/null
fi

echo "https://$domain/$pacfile"
