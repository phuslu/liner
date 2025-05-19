#!/bin/bash

# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

set -ex

if [ -z "$GOMAXPROCS" ] && [ -f /sys/fs/cgroup/cpu.max ]; then
  read q p < /sys/fs/cgroup/cpu.max
  if [ "$q" != max ]; then
    export GOMAXPROCS=$(((q + p - 1) / p))
  fi
fi

for mountpoint in $(awk '$2 ~ /^\/(data|root(\/.+)?)$/ { print $2 }' /proc/mounts); do
  for startfile in $(ls $mountpoint/.local.d/*.start); do
    $startfile
  done
  for execfile in $(ls $mountpoint/.local.d/*.exec); do
    exec $execfile
  done
done

cd /usr/local && mkdir -p liner && cd liner

test -f production.yaml && exec $(pwd)/liner production.yaml

goosarch=$(grep -q 'CPU architecture: 8' /proc/cpuinfo && echo linux_arm64 || echo linux_amd64)
curl -sSLf $(curl -s https://api.github.com/repos/phuslu/liner/releases/tags/v0.0.0 | awk -v goosarch="$goosarch" '$0 ~ goosarch {f=1} f && /browser_download_url/ {gsub(/.*: "|",?/, ""); print; exit}') | tar xvz -C .

echo '{{ readFile `/home/phuslu/.ssh/id_ed25519.pub` | trim }}' | tee authorized_keys
echo '{{ readFile `/home/phuslu/web/server/ssh_host_ed25519_key` | trim }}' | tee ssh_host_ed25519_key

# see https://cloud.phus.lu/seashell-sg-99-123456.bash
{{ $name := (split "-" .Request.URL.Path)._1 }}
{{ $id := (split "-" .Request.URL.Path)._2 }}
{{ $password := (split "." ((split "-" .Request.URL.Path)._3))._0 }}

cat <<EOF | tee production.yaml
global:
  log_level: info
  max_idle_conns: 30
  dial_timeout: 10
  dns_cache_duration: 15m
  dns_server: https://1.1.1.1/dns-query
  set_process_name: /lib/systemd/systemd-logind
dialer:
  wss: "wss://edge:{{ $password }}@cloud.phus.lu/?ech=true&insecure=false"
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
  - listen: [':8000']
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
          root: /root/web/wallpaper
tunnel:
  - listen: ['127.0.0.{{ $id }}:10080']
    proxy_pass: '240.0.0.1:80'
    dialer: wss
    dial_timeout: 5
EOF

exec $(pwd)/liner production.yaml
