# A seashell buried in the sand, meant only to hear the sea at night.
# see https://hub.docker.com/r/phuslu/seashell/

# sudo nerdctl run -d --restart=always --name buildkitd  --privileged -v /var/lib/buildkit:/var/lib/buildkit -v /run/buildkit:/run/buildkit moby/buildkit:latest --addr unix:///run/buildkit/buildkitd.sock
# curl -sSLf https://github.com/moby/buildkit/releases/download/v0.21.0/buildkit-v0.21.0.linux-arm64.tar.gz | sudo tar xvz -C /usr/local/bin/ --strip-components=1 --wildcards bin/buildctl
# sudo nerdctl build --no-cache -f seashell.dockerfile -t phuslu/seashell --platform linux/amd64,linux/arm64 --output type=image,oci-mediatypes=true,compression=zstd,compression-level=19,push=true,name=docker.io/phuslu/seashell .

FROM debian:stable-slim
RUN \
  export DEBIAN_FRONTEND=noninteractive && \
  apt update -y && \
  apt upgrade -y && \
  apt install -y \
    bind9-dnsutils \
    curl \
    dropbear \
    htop \
    iproute2 \
    iputils-ping \
    jq \
    locales \
    lsb-release \
    net-tools \
    openssh-client \
    procps \
    rsync \
    runit \
    sudo \
    tmux \
    util-linux \
    vim-tiny \
    wget && \
  rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
  # set locale
  echo "LC_ALL=en_US.UTF-8" >> /etc/environment && \
  echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
  echo "LANG=en_US.UTF-8" > /etc/locale.conf && \
  locale-gen en_US.UTF-8 && \
  # set bash profile for root
  echo '. $HOME/.bashrc' >/root/.bash_profile && \
  curl -sSlf https://phus.lu/bashrc >/root/.bashrc && \
  # add cloudinit to runit services
  mkdir /etc/service/cloudinit && \
  echo '#!/bin/bash\ntest -n "$cloudinit" && exec bash <(curl -sSlf "$cloudinit")' >/etc/service/cloudinit/run && \
  chmod +x /etc/service/cloudinit/run

ENTRYPOINT ["/usr/bin/runsvdir", "-P ", "/etc/service"]
