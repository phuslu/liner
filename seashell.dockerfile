# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

# sudo nerdctl run -d --restart=always --name buildkitd  --privileged -v /var/lib/buildkit:/var/lib/buildkit -v /run/buildkit:/run/buildkit moby/buildkit:latest --addr unix:///run/buildkit/buildkitd.sock
# curl -sSLf https://github.com/moby/buildkit/releases/download/v0.21.0/buildkit-v0.21.0.linux-arm64.tar.gz | sudo tar xvz -C /usr/local/bin/ --strip-components=1 --wildcards bin/buildctl
# sudo nerdctl build --no-cache -f seashell.dockerfile -t phuslu/seashell --platform linux/amd64,linux/arm64 --output type=image,oci-mediatypes=true,compression=zstd,compression-level=22,push=true,name=docker.io/phuslu/seashell .

FROM alpine:edge
RUN apk add --update --no-cache \
    bash \
    bind-tools \
    curl \
    gcompat \
    grep \
    htop \
    iproute2 \
    jq \
    less \
    lsblk \
    lscpu \
    openssh-client \
    openssl \
    procps \
    rsync \
    runit \
    sudo \
    tini \
    tmux \
    wget \
    xz && \
  rm -rf /var/cache/apk/* && \
  # set bash profile for root
  sed -i 's#root:x:0:0:root:/root:/bin/sh#root:x:0:0:root:/root:/bin/bash#g' /etc/passwd && \
  echo '. $HOME/.bashrc' >/root/.bash_profile && \
  curl -sSlf https://phus.lu/bashrc >/root/.bashrc && \
  # seashell entrypoint
  rm -rf /etc/service && \
  ln -s /root/service /etc/service && \
  printf '#!/bin/sh\n%s\n%s' "# $(date)" 'test -n "$cloudinit" && curl -sSlf "$cloudinit" | bash; exec runsvdir -P /root/service' | tee /seashell.sh

CMD ["/bin/sh", "/seashell.sh"]
