module liner

go 1.26.4

require (
	github.com/coder/websocket v1.8.15
	github.com/go-task/slim-sprig/v3 v3.0.0
	github.com/goccy/go-yaml v1.19.2
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/mileusna/useragent v1.3.5
	github.com/oschwald/maxminddb-golang/v2 v2.4.1
	github.com/phuslu/fastdns v0.17.0
	github.com/phuslu/geosite v1.0.20250901
	github.com/phuslu/gosh v0.0.0-20260528105038-250a6b893c6d
	github.com/phuslu/log v1.0.127
	github.com/phuslu/lru v1.0.21
	github.com/phuslu/pty v0.0.0-20260518141308-9cb014534fff
	github.com/phuslu/tcp-brutal v1.0.1
	github.com/pkg/sftp v1.13.11
	github.com/puzpuzpuz/xsync/v4 v4.5.0
	github.com/quic-go/quic-go v0.60.0
	github.com/refraction-networking/utls v1.8.2
	github.com/robfig/cron/v3 v3.0.1
	github.com/smallnest/ringbuffer v0.1.1
	github.com/valyala/bytebufferpool v1.0.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	gvisor.dev/gvisor v0.0.0-20260715073107-67db8f16ca32
)

require (
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/klauspost/compress v1.19.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20260709172345-9ea1abe57597 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	mvdan.cc/sh/v3 v3.13.1 // indirect
)

replace github.com/quic-go/quic-go v0.60.0 => github.com/phuslu/quic-go v0.0.0-20260715161852-aa767632e13b
