#!/bin/bash

set -ex

cd "$(dirname "$0")"
PROJECT=liner
BUILDROOT=build

REVSION=$(git rev-list --count HEAD)
LDFLAGS="-s -w -X main.version=${REVSION}"
SOURCES="README.md china.pac autoindex.html example.yaml liner-vector.yaml liner-vector.service"

GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}
CGO_ENABLED=${CGO_ENABLED:-$(go env CGO_ENABLED)}

if [ "${GOOS}" == "windows" ]; then
    SOURCES="README.md china.pac example.yaml liner-gui.exe"
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    GOEXE=.exe
elif [ "${GOOS}" == "darwin" ]; then
    SOURCES="README.md china.pac example.yaml"
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
elif [ "${GOARCH:0:3}" == "arm" ]; then
    if [ "$GOARCH" == "arm64" ]; then
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    else
        BUILDDIR=${BUILDROOT}/${GOOS}_armv${GOARM}
        DISTFILE=${PROJECT}_${GOOS}_armv${GOARM}-${REVSION}
    fi
elif [ "${GOARCH:0:4}" == "mips" ]; then
    if [ "$GOMIPS" == "softfloat" ]; then
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}_${GOMIPS}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}_${GOMIPS}-${REVSION}
    else
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    fi
else
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
fi

build () {
    # go build
    mkdir -p ${BUILDDIR}
    env GOOS=${GOOS} \
        GOARCH=${GOARCH} \
        CGO_ENABLED=${CGO_ENABLED} \
    go build -v -trimpath -ldflags="${LDFLAGS}" -o ${BUILDDIR}/${PROJECT}${GOEXE} .
    # go test
    # go test -v .
    # cp files
    cp -r ${SOURCES} ${BUILDDIR}
    # changelog
    git log --oneline --pretty=format:"%h %s" -5 | tee ${BUILDDIR}/CHANGELOG
}

dist () {
    pushd ${BUILDDIR}
    tar cv * | gzip -9 >../${DISTFILE}.tar.gz
    # test ${GOOS}_${GOARCH} = linux_amd64 && tar cv * | xz -9 >../${DISTFILE}.tar.xz
    popd
}

wheel () {
    mkdir pyliner
    env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -v -trimpath -ldflags="${LDFLAGS}" -buildmode=c-shared -o pyliner/pyliner_linux_x86_64.pyd
    # env CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -v -trimpath -ldflags="${LDFLAGS}" -buildmode=c-shared -o pyliner/pyliner_linux_aarch64.pyd
    # env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -v -trimpath -ldflags="${LDFLAGS}" -buildmode=c-shared -o pyliner/pyliner_darwin_x86_64.pyd
    # env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -v -trimpath -ldflags="${LDFLAGS}" -buildmode=c-shared -o pyliner/pyliner_windows_x86_64.pyd
    echo '
import os, platform, ctypes;
libpyliner = ctypes.CDLL(os.path.join(os.path.dirname(__file__), ("pyliner_"+platform.system()+"_"+platform.machine()+".pyd").lower()))
' | tee pyliner/__init__.py
    echo '
from . import libpyliner
libpyliner.Start()
' | tee pyliner/__main__.py
    echo "
[build-system]
requires = ['setuptools', 'wheel']
build-backend = 'setuptools.build_meta'

[project]
name = 'pyliner'
version = '${REVSION}'
description = 'python bindings for liner'
dependencies = []

[tool.setuptools]
include-package-data = true

[tool.setuptools.packages.find]
where = ['.']

[tool.setuptools.package-data]
'pyliner' = ['*.pyd']
" | tee pyproject.toml
    python3 -m venv .venv
    export PATH=$(pwd)/.venv/bin:$PATH
    pip install build
    python3 -m build
    mv dist/pyliner-${REVSION}-py3-none-any.whl build/
}

clean () {
    rm -rf ${BUILDDIR}
    rmdir ${BUILDROOT} || true
}

for a in $@; do $a; done
