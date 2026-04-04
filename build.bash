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
	# http3 patch
	# https://github.com/quic-go/quic-go/issues/5325#issuecomment-3852795180
	github_com_quic_go="${GOPATH}/pkg/mod/$(go list -m github.com/quic-go/quic-go | tr ' ' @)"
	chmod -R +w ${github_com_quic_go}
	sed -i -E 's/packetThreshold = .+/packetThreshold = 32/' ${github_com_quic_go}/internal/ackhandler/sent_packet_handler.go
	grep -m1 packetThreshold ${github_com_quic_go}/internal/ackhandler/sent_packet_handler.go

	go build -v -trimpath
	go test -v

	rm -rf build
	mkdir -p build/liner_{linux_amd64,linux_arm64,linux_armv7,darwin_amd64,darwin_arm64,android_arm64,windows_amd64,windows_arm64}

	git log --oneline --pretty=format:"%h %s" -10 | tee build/changelog.txt

	cat <<EOF | parallel --line-buffer
GOOS=linux GOARCH=amd64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_linux_amd64/liner && \
	cp example.yaml liner@.service build/changelog.txt build/liner_linux_amd64/ && \
	cd build/liner_linux_amd64 && \
	tar cv * | gzip -9 >../liner_linux_amd64-${REVSION}.tar.gz

GOOS=linux GOARCH=arm64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -gcflags='liner=-N' -o build/liner_linux_arm64/liner && \
	upx -9 build/liner_linux_arm64/liner && \
	cp example.yaml liner@.service build/changelog.txt build/liner_linux_arm64/ && \
	cd build/liner_linux_arm64 && \
	tar cv * | gzip -9 >../liner_linux_arm64-${REVSION}.tar.gz

GOOS=linux GOARCH=arm GOARM=7 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -gcflags='liner=-N' -o build/liner_linux_armv7/liner&& \
	upx -9 build/liner_linux_armv7/liner && \
	cp example.yaml build/changelog.txt build/liner_linux_armv7/ && \
	cd build/liner_linux_armv7 && \
	tar cv * | gzip -9 >../liner_linux_armv7-${REVSION}.tar.gz

GOOS=darwin GOARCH=amd64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_darwin_amd64/liner && \
	cp example.yaml build/changelog.txt build/liner_darwin_amd64/ && \
	cd build/liner_darwin_amd64 && \
	tar cv * | gzip -9 >../liner_darwin_amd64-${REVSION}.tar.gz

GOOS=darwin GOARCH=arm64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_darwin_arm64/liner && \
	cp example.yaml build/changelog.txt build/liner_darwin_arm64/ && \
	cd build/liner_darwin_arm64 && \
	tar cv * | gzip -9 >../liner_darwin_arm64-${REVSION}.tar.gz

GOOS=android GOARCH=arm64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_android_arm64/liner && \
	cp example.yaml build/changelog.txt build/liner_android_arm64/ && \
	cd build/liner_android_arm64 && \
	tar cv * | gzip -9 >../liner_android_arm64-${REVSION}.tar.gz

GOOS=windows GOARCH=amd64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_windows_amd64/liner.exe && \
	cp example.yaml liner-gui.exe build/changelog.txt build/liner_windows_amd64/ && \
	cd build/liner_windows_amd64 && \
	tar cv * | gzip -9 >../liner_windows_amd64-${REVSION}.tar.gz

GOOS=windows GOARCH=arm64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -o build/liner_windows_arm64/liner.exe && \
	cp example.yaml liner-gui.exe build/changelog.txt build/liner_windows_arm64/ && \
	cd build/liner_windows_arm64 && \
	tar cv * | gzip -9 >../liner_windows_arm64-${REVSION}.tar.gz
EOF

	rm -rf build/changelog.txt $(find build -mindepth 1 -maxdepth 1 -type d -name "liner_*")
}

function liner::python() {
	rm -rf python && unzip python.zip -d python && pushd python

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
	rm -rf python && unzip python.zip -d python && pushd python

	export CGO_ENABLED=1
	export GOROOT=${GOROOT:-/tmp/go}
	export GOPATH=${GOPATH:-/tmp/gopath}
	export GOOS=windows
	export GOARCH=amd64
	export CC=x86_64-w64-mingw32-gcc
	export CGO_LDFLAGS="-static -static-libgcc -static-libstdc++"
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH
	export REVSION=$(git rev-list --count HEAD)

	mv liner_py-1.0.1984.dist-info liner_py-1.0.${REVSION}.dist-info

	command -v x86_64-w64-mingw32-gcc || apt install -y mingw-w64

	if command -v garble; then
		export GOGARBLE=liner
		GO="garble -literals -tiny -seed=${GARBLE_SEED:-random}"
	else
		GO=go
	fi

	$GO build -v -trimpath -ldflags="-s -w -X main.version=1.0.${REVSION} -X main.garble=${GOGARBLE}" -buildmode=c-shared -o liner.dll ..
	mv liner.dll liner/liner.dll
	cat <<EOF | tee liner/liner.py
import os, ctypes
__dll = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'liner.dll'))
liner = __dll.liner
linex = __dll.linex
EOF

	sed -i "s/^Version: .*/Version: 1.0.${REVSION}/" liner_py-1.0.${REVSION}.dist-info/METADATA
	sed -i "s/Tag: cp32-abi3-.*/Tag: cp32-abi3-win_amd64/" liner_py-1.0.${REVSION}.dist-info/WHEEL

	find liner liner_py-1.0.${REVSION}.* -type f ! -name 'RECORD' -exec sh -c '
		for f; do
		  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
		  hash=$(openssl dgst -sha256 -binary "$f" | openssl base64 | tr -d "\n=")
		  echo "${f#./},sha256=$hash,$size"
		done
		echo liner_py-1.0.${REVSION}.dist-info/RECORD,,
	' sh {} + | tee liner_py-1.0.${REVSION}.dist-info/RECORD

	zip -r liner_py-1.0.${REVSION}-cp32-abi3-win_amd64.whl liner liner_py-1.0.${REVSION}.*

	popd
}

function liner::release() {
	if ls python/liner_py-*.whl 2>/dev/null; then
		pushd python
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep '^liner_py-' | grep "_$(uname -m).whl$" | xargs -i gh release delete-asset v0.0.0 {} --yes
		gh release upload v0.0.0 liner_py-*.whl --clobber
		if git log -1 --oneline | grep -q ' +pypi$'; then
			apt install -yq python3-virtualenv
			virtualenv ~/.venv
			~/.venv/bin/pip install twine
			~/.venv/bin/twine upload liner_py-*.whl
		fi
		popd
	else
		pushd build
		sha1sum liner_*.tar.gz >checksums.txt
		git log --oneline --pretty=format:"%h %s" -5 | tee changelog.txt
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep -v '^liner_py-' | xargs -i gh release delete-asset v0.0.0 {} --yes
		gh release upload v0.0.0 liner_*.tar.gz checksums.txt --clobber
		gh release edit v0.0.0 --notes-file changelog.txt
		popd
	fi
}

liner::$1
