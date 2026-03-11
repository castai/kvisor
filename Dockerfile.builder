################################################################################
# INSTRUCTIONS
################################################################################
#
# This Dockerfile is meant to create a building/exec environment for tracee.
#
################################################################################

FROM ubuntu:noble@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

ARG uid=1000
ARG gid=1000

# ubuntu has been extremely slow with the default archive

#RUN echo "deb http://br.archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" > /etc/apt/sources.list && \
#    echo "deb http://br.archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list

# install needed environment

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y sudo coreutils findutils && \
    apt-get install -y bash git curl rsync && \
    apt-get install -y build-essential clang-14 make pkg-config && \
    apt-get install -y linux-headers-generic && \
    apt-get install -y libelf-dev && \
    apt-get install -y zlib1g-dev && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 140 --slave /usr/bin/clang++ clang++ /usr/bin/clang++-14 --slave /usr/bin/llc llc /usr/bin/llc-14 --slave /usr/bin/clang-format clang-format /usr/bin/clang-format-14 --slave /usr/bin/clangd clangd /usr/bin/clangd-14

# extra tools for testing things

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y bash-completion vim && \
    apt-get install -y iproute2 vlan bridge-utils net-tools && \
    apt-get install -y netcat-openbsd iputils-ping && \
    apt-get install -y wget lynx w3m && \
    apt-get install -y stress && \
    apt-get install -y dnsutils

ARG TARGETARCH
RUN export DEBIAN_FRONTEND=noninteractive && \
    curl -L -o /tmp/golang.tar.xz https://go.dev/dl/go1.21.5.linux-$TARGETARCH.tar.gz && \
    tar -C /usr/local -xzf /tmp/golang.tar.xz && \
    update-alternatives --install /usr/bin/go go /usr/local/go/bin/go 1 && \
    rm /tmp/golang.tar.xz

RUN export DEBIAN_FRONTEND=noninteractive && \
    curl -L -o /tmp/bpftool.tar.xz https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool-v7.3.0-$TARGETARCH.tar.gz && \
    tar -C /usr/bin -xzf /tmp/bpftool.tar.xz && \
    chmod +x /usr/bin/bpftool && \
    rm /tmp/bpftool.tar.xz

ENV HOME /home
WORKDIR /home/app
