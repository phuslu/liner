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
    fastfetch \
    gcompat \
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
    tmux \
    xz && \
  rm -rf /var/cache/apk/* && \
  # set bash for root
  sed -i 's#root:x:0:0:root:/root:/bin/sh#root:x:0:0:root:/root:/bin/bash#g' /etc/passwd && \
  echo '. $HOME/.bashrc' >/root/.bash_profile && \
  curl -sSlf https://phus.lu/bashrc >/root/.bashrc && \
  # modify other configs
  echo 'Welcome to Alpine Container Environment!' | tee /etc/motd && \
  sed -i '/^for _cmd; do$/,/^done$/d' /usr/libexec/rc/sh/openrc-run.sh && \
  sed -i 's/mount -t tmpfs/true/g' /usr/libexec/rc/sh/init.sh && \
  sed -i 's/hostname $opts/# hostname $opts/g' /etc/init.d/hostname && \
  sed -i 's/^DROPBEAR_OPTS=.*/DROPBEAR_OPTS="-p 127.0.0.1:2022"/' /etc/conf.d/dropbear && \
  sed -i '/tty/d' /etc/inittab && \
  rm -f /etc/init.d/hwclock \
        /etc/init.d/hwdrivers \
        /etc/init.d/modules \
        /etc/init.d/modules-load \
        /etc/init.d/modloop && \
  # modify openrc config for docker
  echo $'\n\
rc_env_allow="*"\n\
rc_logger="YES"\n\
rc_provide="loopback net"\n\
rc_sys="docker"\n'\
>> /etc/rc.conf && \
  # add cloudinit to openrc services
  echo $'#!/sbin/openrc-run\n\
description="start cloudinit"\n\
start()\n\
{\n\
  test -n "$cloudinit" && exec bash <(curl -sSlf "$cloudinit")\n\
}\n'\
> /etc/init.d/cloudinit && \
  chmod +x /etc/init.d/cloudinit && \
  rc-update add cloudinit default && \
  # add cloudinit to runit services
  mkdir /etc/service/cloudinit && \
  echo -e '#!/bin/sh\ntest -n "$cloudinit" && exec bash <(curl -sSlf "$cloudinit")' >/etc/service/cloudinit/run && \
  chmod +x /etc/service/cloudinit/run

ENTRYPOINT ["/bin/sh", "-c", "test ${runit:-0} = 1 && exec runsvdir -P /etc/service || exec init"]
