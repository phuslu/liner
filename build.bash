#!/bin/bash -xe

function setup() {
	export DEBIAN_FRONTEND=noninteractive
	apt update -y
	apt install -yq git curl jq zip bzip2 xz-utils gh build-essential python3-pip python3-venv python3-dev

	git config --global --add safe.directory '*'

	goarch=$(test $(uname -m) = aarch64 && echo arm64 || echo amd64)

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/go1.24.linux-${goarch}.tar.xz | \
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
	export GOROOT=/tmp/go
	export GOPATH=/tmp/gopath
	export PATH=${GOPATH:-~/go}/bin:${GOROOT}/bin:$PATH

	go install -v mvdan.cc/garble@latest

	env GOGARBLE=liner python3 setup.py bdist_wheel

	python3 -m venv ~/.venv
	~/.venv/bin/pip install auditwheel
	~/.venv/bin/auditwheel repair wheel/dist/liner-*.whl

	mkdir -p build
	mv wheelhouse/liner-*.whl build/
}

function release() {
	pushd build

	if ls liner_*; then
		sha1sum liner* >checksums.txt
		git log --oneline --pretty=format:"%h %s" -5 | tee changelog.txt
		gh release view v0.0.0 --json assets --jq .assets[].name | egrep '^liner_' | xargs -i gh release delete-asset v0.0.0 {} --yes
		gh release upload v0.0.0 liner_* checksums.txt --clobber
		gh release edit v0.0.0 --notes-file changelog.txt
	elif ls liner-*.whl; then
		gh release upload v0.0.0 liner-*.whl --clobber
	fi

	popd
}


$1
