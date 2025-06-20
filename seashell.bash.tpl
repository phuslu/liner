#!/bin/bash

# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

set -ex

test -x ~/service/liner/run && exit 0

cd && mkdir -p liner && cd liner

goosarch=$(grep -q 'CPU architecture: 8' /proc/cpuinfo && echo linux_arm64 || echo linux_amd64)
curl -sSLf $(curl -s https://api.github.com/repos/phuslu/liner/releases/tags/v0.0.0 | awk -v goosarch="$goosarch" '$0 ~ goosarch {f=1} f && /browser_download_url/ {gsub(/.*: "|",?/, ""); print; exit}') | tar xvz -C .

echo '{{ readFile `/home/phuslu/.ssh/id_ed25519.pub` | trim }}' | tee authorized_keys
echo '{{ readFile `/home/phuslu/web/server/ssh_host_ed25519_key` | trim }}' | tee ssh_host_ed25519_key

# see https://cloud.phus.lu/seashell-sg-99-123456-8000.bash
{{ $pathparts := .Request.URL.Path | trimPrefix "/" | trimSuffix ".bash" | split "-" }}
{{ $name := $pathparts._1 }}
{{ $id := $pathparts._2 }}
{{ $password := $pathparts._3 }}
{{ $port := $pathparts._4 }}

cat <<EOF | tee production.yaml
# {{ $name }}
global:
  log_level: info
  max_idle_conns: 30
  dial_timeout: 10
  dns_cache_duration: 15m
  dns_server: https://8.8.8.8/dns-query
  set_process_name: /lib/systemd/systemd-logind
dialer:
  wss: "wss://edge:{{ $password }}@cloud.phus.lu/?ech=true&insecure=false"
tunnel:
  - listen: ['127.0.0.{{ $id }}:10080']
    proxy_pass: '240.0.0.1:80'
    dialer: wss
    dial_timeout: 5
ssh:
  - listen: ['240.0.0.1:22']
    host_key: ssh_host_ed25519_key
    authorized_keys: authorized_keys
    shell: /bin/bash
    log: true
http:
  - listen: ['240.0.0.1:80']
    forward:
      policy: bypass_auth
{{ if $port }}
  - listen: [':{{ $port }}']
    server_name: ['{{ $name }}.edge.phus.lu']
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
EOF

if test -f /seashell.sh; then
  mkdir -p ~/service/liner
  echo -e '#!/bin/bash\ncd ~/liner && exec $(pwd)/liner production.yaml' >  ~/service/liner/run
  chmod +x ~/service/liner/run
else
  echo -e 'while :; do env GOMAXPROCS=2 $(pwd)/liner production.yaml; sleep 2; done' > keepalive
  exec /bin/sh keepalive
fi
