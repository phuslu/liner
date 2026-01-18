module liner

go 1.26

require (
	github.com/coder/websocket v1.8.14
	github.com/creack/pty/v2 v2.0.1
	github.com/go-task/slim-sprig/v3 v3.0.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/mileusna/useragent v1.3.5
	github.com/oschwald/maxminddb-golang/v2 v2.1.1
	github.com/phuslu/fastcgi v0.0.0-20231004164338-7aec0d4ba593
	github.com/phuslu/fastdns v0.16.4
	github.com/phuslu/geosite v1.0.20250901
	github.com/phuslu/log v1.0.121
	github.com/phuslu/lru v1.0.18
	github.com/pkg/sftp v1.13.10
	github.com/puzpuzpuz/xsync/v4 v4.3.0
	github.com/quic-go/quic-go v0.59.0
	github.com/refraction-networking/utls v1.8.2
	github.com/robfig/cron/v3 v3.0.1
	github.com/smallnest/ringbuffer v0.0.0-20250317021400-0da97b586904
	github.com/valyala/bytebufferpool v1.0.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.47.0
	golang.org/x/net v0.49.0
	golang.org/x/sys v0.40.0
	gopkg.in/yaml.v3 v3.0.1
	mvdan.cc/sh/v3 v3.12.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/term v0.39.0 // indirect
	golang.org/x/text v0.33.0 // indirect
)

replace github.com/creack/pty/v2 v2.0.1 => github.com/photostorm/pty/v2 v2.0.0-20240405180724-bf40468acd65
