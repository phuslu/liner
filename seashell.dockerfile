# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

# sudo nerdctl run -d --restart=always --name buildkitd  --privileged -v /var/lib/buildkit:/var/lib/buildkit -v /run/buildkit:/run/buildkit moby/buildkit:latest --addr unix:///run/buildkit/buildkitd.sock
# curl -sSLf https://github.com/moby/buildkit/releases/download/v0.21.0/buildkit-v0.21.0.linux-arm64.tar.gz | sudo tar xvz -C /usr/local/bin/ --strip-components=1 --wildcards bin/buildctl
# sudo nerdctl build --no-cache -f seashell.dockerfile -t phuslu/seashell --platform linux/amd64,linux/arm64 --output type=image,oci-mediatypes=true,compression=zstd,compression-level=19,push=true,name=docker.io/phuslu/seashell .

FROM alpine:3.21
RUN \
  apk update && \
  apk upgrade && \
  apk add --update --no-cache \
    bash \
    bind-tools \
    busybox-openrc \
    curl \
    dropbear \
    gcompat \
    grep \
    htop \
    iproute2 \
    jq \
    logrotate \
    lsblk \
    lscpu \
    openrc \
    openssh-client \
    openssl \
    procps \
    rsync \
    runit \
    runit-openrc \
    sudo \
    tini \
    tmux \
    xz && \
  rm -rf /var/cache/apk/* && \
  # set bash profile for root
  sed -i 's#root:x:0:0:root:/root:/bin/sh#root:x:0:0:root:/root:/bin/bash#g' /etc/passwd && \
  echo '. $HOME/.bashrc' >/root/.bash_profile && \
  curl -sSlf https://phus.lu/bashrc >/root/.bashrc && \
  # modify other configs
  echo 'Welcome to Alpine Container Environment!' | tee /etc/motd && \
  # add cloudinit to runit services
  mkdir /etc/service/cloudinit && \
  echo -e '#!/bin/bash\ntest -n "$cloudinit" && exec bash <(curl -sSlf "$cloudinit")' >/etc/service/cloudinit/run && \
  chmod +x /etc/service/cloudinit/run

ENTRYPOINT ["/usr/bin/runsvdir", "-P ", "/etc/service"]
