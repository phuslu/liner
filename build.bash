#!/bin/bash -xe

function liner::setup() {
	export DEBIAN_FRONTEND=noninteractive
	if test -f /etc/alpine-release; then
		apk update
		apk add git curl jq unzip zip xz github-cli patch make build-base parallel upx
	else
		apt update -y
		apt install -yq git curl jq unzip zip xz-utils gh build-essential parallel upx
	fi

	git config --global --add safe.directory '*'

	goarch=$(test $(uname -m) = aarch64 && echo arm64 || echo amd64)

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/gotip.linux-${goarch}.tar.xz | \
	tar xvJ -C /tmp/
}

function liner::build() {
	rm -rf build && mkdir build

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
	golang_org_x_net="${GOPATH}/pkg/mod/$(go list -m golang.org/x/net | tr ' ' @)"
	chmod -R +w ${golang_org_x_net}
	patch -p1 -d ${golang_org_x_net} <http2date.patch

	go build -v -trimpath
	go test -v

	mkdir \
		build/liner_linux_amd64 \
		build/liner_linux_arm64 \
		build/liner_linux_armv7 \
		build/liner_darwin_amd64 \
		build/liner_darwin_arm64 \
		build/liner_android_arm64 \
		build/liner_windows_amd64 \
		build/liner_windows_arm64

	git log --oneline --pretty=format:"%h %s" -10 | tee build/changelog.txt

	cat <<EOF | parallel --line-buffer
GOOS=linux GOARCH=amd64 \
	go build -v -trimpath -ldflags='-s -w -X main.version=1.0.${REVSION}' -gcflags='liner=-N' -o build/liner_linux_amd64/liner && \
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
			export CGO_CFLAGS="-I/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Headers/"
			export CGO_LDFLAGS="-L/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/ -lpython3.9"
			export PLATFORM_TAG="macosx_11_0_x86_64"
			;;
		Linux )
			export CGO_CFLAGS="$(python3-config --includes)"
			export CGO_LDFLAGS="$(python3-config --ldflags)"
			export PLATFORM_TAG="manylinux_2_34_$(arch)"
			;;
	esac

	#go install -v mvdan.cc/garble@latest
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
			perl -pi -e "s/Tag: cp39-abi3-.*/Tag: cp39-abi3-macosx_11_0_x86_64/" liner_py-1.0.${REVSION}.dist-info/WHEEL
			;;
		Linux )
			sed -i "s/^Version: .*/Version: 1.0.${REVSION}/" liner_py-1.0.${REVSION}.dist-info/METADATA
			sed -i "s/Tag: cp39-abi3-.*/Tag: cp39-abi3-linux_$(arch)/" liner_py-1.0.${REVSION}.dist-info/WHEEL
			;;
	esac

	find liner liner_py-1.0.${REVSION}.dist-info -type f ! -name 'RECORD' -exec sh -c '
		for f; do
		  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
		  hash=$(openssl dgst -sha256 -binary "$f" | openssl base64 | tr -d "\n=")
		  echo "${f#./},sha256=$hash,$size"
		done
		echo liner_py-1.0.${REVSION}.dist-info/RECORD,,
	' sh {} + | tee liner_py-1.0.${REVSION}.dist-info/RECORD

	zip -r liner_py-1.0.${REVSION}-cp39-abi3-${PLATFORM_TAG}.whl liner liner_py-1.0.${REVSION}.dist-info

	popd
}

function liner::release() {
	if ls python/liner_py-*.whl 2>/dev/null; then
		pushd python
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep '^liner_py-' | grep "_$(arch).whl$" | xargs -i gh release delete-asset v0.0.0 {} --yes
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
