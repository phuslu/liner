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
    rm -rf wheel && mkdir -p wheel/liner
    GO_LDFLAGS="-s -w -X main.version=${REVSION}"
    if [ "$(go env GOOS)" == "darwin" ]; then
        GO_LDFLAGS="${GO_LDFLAGS} -linkmode external -extldflags '-Wl,-install_name,@rpath/libliner.so'"
    fi
    env CGO_ENABLED=1 go build -v -trimpath -ldflags="${GO_LDFLAGS}" -buildmode=c-shared -o wheel/liner/libliner.so
    touch wheel/liner/__init__.py
    echo '
from . import liner
liner.start()
' | tee wheel/liner/__main__.py
    echo '
#define Py_LIMITED_API 0x03090000
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "libliner.h"
static PyObject* start(PyObject *self, PyObject *args) {
    Start();
    Py_RETURN_NONE;
}
static PyMethodDef StartMethods[] = {
    {"start", start, METH_NOARGS, "start liner"},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef startmodule = {
    PyModuleDef_HEAD_INIT,
    "liner",
    NULL,
    -1,
    StartMethods
};
PyMODINIT_FUNC PyInit_liner(void) {
    return PyModule_Create(&startmodule);
}
' | tee wheel/liner/liner.c
    echo "
import platform
from setuptools import setup, Extension
liner_extension = Extension(
    'liner.liner',
    define_macros=[('Py_LIMITED_API', '0x03090000')],
    sources=['liner/liner.c'],
    include_dirs=['./liner'],
    library_dirs=['./liner'],
    libraries=['liner'],
    extra_link_args=['-Wl,-rpath,' + ('@loader_path' if platform.system() == 'Darwin' else '\$ORIGIN')],
    py_limited_api=True,
)
setup(
    name='liner',
    version='${REVSION}',
    description='python bindings for liner',
    packages=['liner'],
    ext_modules=[liner_extension],
    options={'bdist_wheel':{'py_limited_api':'cp39','plat_name':'macosx_11_0_'+platform.machine() if platform.system() == 'Darwin' else None}},
    include_package_data=True,
    package_data={'liner':['libliner.so']},
)
" | tee wheel/setup.py
    cd wheel
    python3 setup.py bdist_wheel
    cd ..
    mv wheel/dist/liner-*.whl build/
}

clean () {
    rm -rf ${BUILDDIR}
    rmdir ${BUILDROOT} || true
}

for a in $@; do $a; done
