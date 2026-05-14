#!/bin/bash -xe

function liner::setup() {
	export DEBIAN_FRONTEND=noninteractive
	apt update -y
	apt install -yq git curl jq unzip zip xz-utils gh build-essential parallel upx

	git config --global --add safe.directory '*'

	goarch=$(test $(uname -m) = aarch64 && echo arm64 || echo amd64)

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/go1.26.linux-${goarch}.tar.xz | \
	tar xvJ -C /tmp/
}

function liner::build() {
	export CGO_ENABLED=0
	export GOOS=${GOOS:-$(go env GOOS)}
	export GOARCH=${GOARCH:-$(go env GOARCH)}
	export GOROOT=${GOROOT:-/tmp/go}
	export GOPATH=${GOPATH:-/tmp/gopath}
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH
	export REVSION=$(git rev-list --count HEAD)

	if grep -lr $(printf '\r\n') * | grep '.go$' ; then
		echo -e "\e[1;31mPlease run dos2unix for go source files\e[0m"
		exit 1
	fi

	# if [ "$(gofmt -l .)" != "" ]; then
	# 	echo -e "\e[1;31mPlease run 'gofmt -s -w .' for go source files\e[0m"
	# 	exit 1
	# fi

	go version
	go env

	go mod download -x
	# http2 patch
	# https://github.com/golang/go/issues/47840#issuecomment-983558795
	sed -i -E 's/const http2bufWriterPoolBufferSize = .+/var http2bufWriterPoolBufferSize = func() int { n, _ := strconv.Atoi(os.Getenv("HTTP2_WRITER_POOL_BUFFER_SIZE")); return max(n, 32768) }()/' ${GOROOT}/src/net/http/h2_bundle.go
	grep -m1 http2bufWriterPoolBufferSize ${GOROOT}/src/net/http/h2_bundle.go
	# x/net/http2 patch
	golang_org_x_net="${GOPATH}/pkg/mod/$(go list -m golang.org/x/net | tr ' ' @)"
	chmod -R +w ${golang_org_x_net}/http2
	sed -i -E 's/const bufWriterPoolBufferSize = .+/var bufWriterPoolBufferSize = func() int { n, _ := strconv.Atoi(os.Getenv("HTTP2_WRITER_POOL_BUFFER_SIZE")); return max(n, 32768) }()/' ${golang_org_x_net}/http2/http2.go
	grep -m1 'var bufWriterPoolBufferSize' ${golang_org_x_net}/http2/http2.go

	go build -v -trimpath
	# go test -v

	rm -rf build
	mkdir -p build

	git log --oneline --pretty=format:"%h %s" -10 | tee build/changelog.txt

		cat <<EOF | tee proxy.yaml
global:
  log_level: info
  log_backups: 2
  log_maxsize: 104857600
  log_localtime: true
  max_idle_conns: 64
dialer:
  sg-http3: "http3://username:password@phus.lu:443/"
http:
  - listen: ['127.0.0.1:8087']
    forward:
      policy: bypass_auth
      dialer: sg-http3
    web:
      - location: /proxy.pac
        index:
          file: china.pac
EOF

	case ${GOOS}_${GOARCH} in
		linux_amd64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner
			cp china.pac proxy.yaml liner@.service build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		linux_arm64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -gcflags='liner=-N' -o build/liner
			upx -9 build/liner
			cp china.pac proxy.yaml liner@.service build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		linux_arm )
			export GOARM=7
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -gcflags='liner=-N' -o build/liner
			upx -9 build/liner
			cp china.pac proxy.yaml build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		darwin_amd64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner
			cp china.pac proxy.yaml liner.command pyobjc.zip build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		darwin_arm64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner
			cp china.pac proxy.yaml liner.command pyobjc.zip build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		android_arm64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner
			cp china.pac proxy.yaml build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		windows_amd64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner.exe
			unzip wintun-0.14.1.zip
			cp china.pac proxy.yaml liner.cmd wintun/bin/${GOARCH}/wintun.dll build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
		windows_arm64 )
			go build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION}" -o build/liner.exe
			unzip wintun-0.14.1.zip
			cp china.pac proxy.yaml liner.cmd wintun/bin/${GOARCH}/wintun.dll build/
			cd build
			tar cv * | gzip -9 >../liner_${GOOS}_${GOARCH}-${REVSION}.tar.gz
			;;
	esac

	rm -rf build/changelog.txt $(find build -mindepth 1 -maxdepth 1 -type d -name "liner_*")
}

function liner::python() {
	rm -rf python && unzip liner-py.zip -d python && pushd python

	export CGO_ENABLED=1
	export GOROOT=${GOROOT:-/tmp/go}
	export GOPATH=${GOPATH:-/tmp/gopath}
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH
	export REVSION=$(git rev-list --count HEAD)

	mv liner_py-1.0.1984.dist-info liner_py-1.0.${REVSION}.dist-info

	case $(uname) in
		Darwin )
			command -v python3-config || brew install python
			export CGO_CFLAGS="$(python3-config --includes)"
			export CGO_LDFLAGS="$(python3-config --ldflags) -undefined dynamic_lookup"
			export PLATFORM_TAG="macosx_11_0_$(uname -m)"
			;;
		Linux )
			command -v python3-config || env DEBIAN_FRONTEND=noninteractive apt install -y python3-dev
			export CGO_CFLAGS="$(python3-config --includes)"
			export CGO_LDFLAGS="$(python3-config --ldflags)"
			export PLATFORM_TAG="manylinux_2_34_$(uname -m)"
			;;
	esac

	if ! command -v garble; then
		if git log -1 --oneline | grep -q ' +garble '; then
			go install -v mvdan.cc/garble@master
		fi
	fi

	if command -v garble; then
		export GOGARBLE=liner
		GO="garble -literals -tiny -seed=${GARBLE_SEED:-random}"
	else
		GO=go
	fi

	$GO build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION} -X main.garble=${GOGARBLE}" -buildmode=c-shared -o liner.so ..
	mv -f liner.so liner/liner.so

	case $(uname) in
		Darwin )
			perl -pi -e "s/^Version: .*/Version: 1.0.${REVSION}/" liner_py-1.0.${REVSION}.dist-info/METADATA
			perl -pi -e "s/Tag: cp32-abi3-.*/Tag: cp32-abi3-macosx_11_0_$(uname -m)/" liner_py-1.0.${REVSION}.dist-info/WHEEL
			;;
		Linux )
			sed -i "s/^Version: .*/Version: 1.0.${REVSION}/" liner_py-1.0.${REVSION}.dist-info/METADATA
			sed -i "s/Tag: cp32-abi3-.*/Tag: cp32-abi3-linux_$(uname -m)/" liner_py-1.0.${REVSION}.dist-info/WHEEL
			;;
	esac

	find liner liner_py-1.0.${REVSION}.* -type f ! -name 'RECORD' -exec sh -c '
		for f; do
		  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
		  hash=$(openssl dgst -sha256 -binary "$f" | openssl base64 | tr -d "\n=")
		  echo "${f#./},sha256=$hash,$size"
		done
		echo liner_py-1.0.${REVSION}.dist-info/RECORD,,
	' sh {} + | tee liner_py-1.0.${REVSION}.dist-info/RECORD

	zip -r liner_py-1.0.${REVSION}-cp32-abi3-${PLATFORM_TAG}.whl liner liner_py-1.0.${REVSION}.*

	popd
}

function liner::python::windows() {
	rm -rf python && unzip liner-py.zip -d python && pushd python

	export CGO_ENABLED=1
	export GOOS=windows
	export GOARCH=${GOARCH:-amd64}
	export GOROOT=${GOROOT:-/tmp/go}
	export GOPATH=${GOPATH:-/tmp/gopath}
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH
	export REVSION=$(git rev-list --count HEAD)
	export CC="zig cc -target $(test $GOARCH = arm64 && echo -n aarch64 || echo -n x86_64)-windows-gnu"

	mv liner_py-1.0.1984.dist-info liner_py-1.0.${REVSION}.dist-info

	if ! command -v zig; then
		curl -sSLf https://download.zigmirror.com/zig-$(uname -m)-linux-0.15.2.tar.xz | tar xvJ -C /tmp/
		export PATH=$PATH:/tmp/zig-$(uname -m)-linux-0.15.2
	fi

	if command -v garble; then
		export GOGARBLE=liner
		GO="garble -literals -tiny -seed=${GARBLE_SEED:-random}"
	else
		GO=go
	fi

	$GO build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION} -X main.garble=${GOGARBLE}" -buildmode=c-shared -o liner.dll ..
	mv liner.dll liner/liner.dll
	cat <<EOF | tee liner/liner.py
import ctypes
import os
dll = ctypes.CDLL(os.path.dirname(__file__) + '/liner.dll')
liner = dll.liner
linex = dll.linex
del ctypes, os, dll
EOF

	sed -i "s/^Version: .*/Version: 1.0.${REVSION}/" liner_py-1.0.${REVSION}.dist-info/METADATA
	sed -i "s/Tag: cp32-abi3-.*/Tag: cp32-abi3-win_${GOARCH}/" liner_py-1.0.${REVSION}.dist-info/WHEEL

	find liner liner_py-1.0.${REVSION}.* -type f ! -name 'RECORD' -exec sh -c '
		for f; do
		  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
		  hash=$(openssl dgst -sha256 -binary "$f" | openssl base64 | tr -d "\n=")
		  echo "${f#./},sha256=$hash,$size"
		done
		echo liner_py-1.0.${REVSION}.dist-info/RECORD,,
	' sh {} + | tee liner_py-1.0.${REVSION}.dist-info/RECORD

	zip -r liner_py-1.0.${REVSION}-cp32-abi3-win_${GOARCH}.whl liner liner_py-1.0.${REVSION}.*

	popd
}

function liner::release() {
	if ls python/liner_py-*.whl 2>/dev/null; then
		pushd python
		# gh release view v0.0.0 --json assets --jq .assets[].name | egrep "^liner_py-.+$(ls liner_py-*_*.whl | awk -F- '{print $NF}')$" | xargs -i gh release delete-asset v0.0.0 {} --yes
		# gh release upload v0.0.0 liner_py-*.whl --clobber
		if git log -1 --oneline | grep -q ' +pypi$'; then
			apt install -yq python3-virtualenv
			virtualenv ~/.venv
			~/.venv/bin/pip install twine
			~/.venv/bin/twine upload liner_py-*.whl
		fi
		popd
	else
		git log --oneline --pretty=format:"%h %s" -5 | tee changelog.txt
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep "^$(ls liner_*_*.tar.gz | awk -F- '{print $1}')-" | xargs -i gh release delete-asset v0.0.0 {} --yes
		gh release upload v0.0.0 liner_*.tar.gz --clobber
		gh release edit v0.0.0 --notes-file changelog.txt
	fi
}

liner::$1
