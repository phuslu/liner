#!/bin/bash

# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

set -ex

test -x ~/service/liner/run && exit 0

test $(pwd) = '/' && cd || true
mkdir -p liner && cd liner

go_os_arch=$(grep -q 'CPU architecture: 8' /proc/cpuinfo && echo linux_arm64 || echo linux_amd64)
download_url=$(wget -O- https://api.github.com/repos/phuslu/liner/releases/tags/v0.0.0 | awk -v go_os_arch="$go_os_arch" '$0 ~ go_os_arch {f=1} f && /browser_download_url/ {gsub(/.*: "|",?/, ""); print; exit}')
wget ${download_url} -O 1.tar.gz && tar xvzf 1.tar.gz && rm -f 1.tar.gz

# echo '{{ readFile `/home/phuslu/web/server/ssh_host_ed25519_key` | trim }}' | tee ssh_host_ed25519_key
echo '{{ readFile `/home/phuslu/.ssh/id_ed25519.pub` | trim }}' | tee phuslu.keys

# see https://cloud.phus.lu/seashell-sg-99-123456-8080.bash
{{ $pathparts := .Request.URL.Path | trimPrefix "/" | trimSuffix ".bash" | split "-" }}
{{ $name := $pathparts._1 }}
{{ $id := $pathparts._2 }}
{{ $proto := empty .Request.TLS | ternary "ws" "wss" }}
{{ $password := $pathparts._3 }}
{{ $port := $pathparts._4 }}

cat <<EOF | tee production.yaml
# {{ $name }}
global:
  log_level: info
  max_idle_conns: 30
  dial_timeout: 10
  geosite_disabled: true
  dns_cache_duration: 15m
  dns_server: https://8.8.8.8/dns-query
  set_process_name: /bin/sleep 60
dialer:
  cloud: "{{ $proto }}://edge:{{ $password }}@{{ .Request.Host }}/?ech=true&insecure=false"
http:
{{ if $port }}
  - listen: ['0.0.0.0:{{ $port }}']
    server_name: ['*']
    web:
      - location: /jsonp
        index:
          headers: |
            content-type: application/json;charset=utf-8
          body: |
            {{"{{"}} .Request.URL.Query.Get "callback" -{{"}}"}}({{"{{"}} (fetch .Request.UserAgent 10 (default 0 (int (.Request.URL.Query.Get "ttl"))) (.Request.URL.Query.Get "url")).Body {{"}}"}})
      - location: /
        index:
          root: /root/web
{{ end }}
  - listen: ['240.0.0.{{ $id }}:80']
    forward:
      policy: bypass_auth
ssh:
  - listen: ['240.0.0.{{ $id }}:22']
    # host_key: /etc/ssh/ssh_host_ed25519_key
    # wget https://github.com/phuslu.keys
    authorized_keys: phuslu.keys
    banner_file: motd
    shell: /bin/bash
    log: true
tunnel:
  - remote_listen: ['240.0.0.{{ $id }}:80']
    proxy_pass: '240.0.0.{{ $id }}:80'
    dialer: cloud
    dial_timeout: 5
  - remote_listen: ['240.0.0.{{ $id }}:22']
    proxy_pass: '240.0.0.{{ $id }}:22'
    dialer: cloud
    dial_timeout: 5
EOF

cat <<'EOF' | tee motd
{{"{{"}} $info := (geoip .RemoteAddr){{"}}"}}
Welcome to Alpine!
ClientVersion: {{"{{"}} .ClientVersion{{"}}"}}
RemoteIP: {{"{{"}} host .RemoteAddr{{"}}"}} {{"{{"}} $info.City{{"}}"}} {{"{{"}} $info.Country{{"}}"}} {{"{{"}} $info.ISP{{"}}"}} {{"{{"}} $info.ConnectionType{{"}}"}}
RTT: {{"{{"}} div (call .RTT) 1000000{{"}}"}} ms
EOF

mkdir -p /root/web || true

if test -f /seashell.sh; then
  mkdir -p ~/service/liner
  echo -e '#!/bin/bash\ncd ~/liner && exec $(pwd)/liner production.yaml' >  ~/service/liner/run
  chmod +x ~/service/liner/run
else
  echo -e 'while :; do test -f .env && . .env ; "$@"; sleep 2; done' > keepalive
  exec /bin/sh keepalive $(pwd)/liner production.yaml
fi
