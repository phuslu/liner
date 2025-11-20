#!/bin/bash -xe

function setup() {
	export DEBIAN_FRONTEND=noninteractive
	if test -f /etc/alpine-release; then
		apk update
		apk add git curl jq zip xz github-cli patch make build-base py3-pip python3-dev patchelf
	else
		apt update -y
		apt install -yq git curl jq zip xz-utils gh build-essential python3-pip python3-venv python3-dev patchelf
	fi

	git config --global --add safe.directory '*'

	goarch=$(test $(uname -m) = aarch64 && echo arm64 || echo amd64)

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/gotip.linux-${goarch}.tar.xz | \
	tar xvJ -C /tmp/
}

function build() {
	export CGO_ENABLED=0
	export GOROOT=/tmp/go
	export GOPATH=/tmp/gopath
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH

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

	go build -v .
	go test -v .

	cat <<EOF |
CGO_ENABLED=0 GOOS=android GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ./make.bash build dist
EOF
	xargs --max-procs=8 -n1 -i bash -c {}

}

function wheel() {
	export CGO_ENABLED=1
	export GOROOT=${GOROOT:-/tmp/go}
	export GOPATH=${GOPATH:-/tmp/gopath}
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH

	#go install -v mvdan.cc/garble@latest
	#export GOGARBLE=liner

	python3 setup.py bdist_wheel

	if [ "$(uname)" = "Linux" ]; then
		if python3 -c "import sys; exit(sys.prefix != getattr(sys, 'base_prefix', sys.prefix))"; then
			python3 -m venv ~/.venv
		fi
		~/.venv/bin/pip install auditwheel
		~/.venv/bin/auditwheel repair wheel/dist/liner*.whl
	fi

	mkdir -p build
	mv wheelhouse/liner*.whl build/
}

function release() {
	pushd build

	if ls liner_*.whl; then
		gh release upload v0.0.0 liner_*.whl --clobber
	elif ls liner_*; then
		sha1sum liner* >checksums.txt
		git log --oneline --pretty=format:"%h %s" -5 | tee changelog.txt
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep '^liner_' | egrep -v '^liner_py-' | xargs -i gh release delete-asset v0.0.0 {} --yes
		gh release upload v0.0.0 liner_* checksums.txt --clobber
		gh release edit v0.0.0 --notes-file changelog.txt
	fi

	popd
}


$1
