// v{{.ServerVersion}} updated at {{.FileInfo.ModTime.Format "2006-01-02T15:04:05Z07:00"}}

var direct = 'DIRECT'
{{if .Request.TLS -}}
var proxy = 'HTTPS {{.Request.Host}}:443'
{{else}}
var proxy = 'HTTP {{.Request.Host}}:8080'
{{end}}

var prelude = {
	{{ .Request.URL.Query.Get "prelude" -}}
	{{ readFile "prelude.txt" -}}
	// wifi captive portal
	"asusrouter.com":0,
	"captive.apple.com":0,
	"connectivitycheck.android.com":0,
	"ipv6.msftconnecttest.com":0,
	"www.msftconnecttest.com":0,
	"www.msftncsi.com":0,
	// direct domains
	"{{domain .Request.Host}}":0,
	"alicdn.com":0,
	"google-analytics.com":0,
	"gtimg.com":0,
	"icloud-content.com":0,
	"mzstatic.com":0,
	"ykimg.com":0,
	// proxy doamins
	"amazon.com":1,
	"amazonaws.com":1,
	"ampproject.org":1,
	"apple.com":1,
	"bit.ly":1,
	"cdninstagram.com":1,
	"cloudapp.net":1,
	"cloudfront.net":1,
	"facebook.com":1,
	"facebook.net":1,
	"fbcdn.net":1,
	"ggpht.com":1,
	"github.com":1,
	"github.io":1,
	"githubassets.com":1,
	"githubusercontent.com":1,
	"google.co.jp":1,
	"google.com":1,
	"google.com.hk":1,
	"google.com.sg":1,
	"googleapis.com":1,
	"googleusercontent.com":1,
	"googlevideo.com":1,
	"gstatic.com":1,
	"gvt2.com":1,
	"linkedin.com":1,
	"twimg.com":1,
	"twitter.com":1,
	"youtube.com":1,
	"ytimg.com":1,
	// dark web
	"onion":1
}

var wildcard = (function(o){var a=[];for(var k in o){if(k.indexOf('*')>=0)a.push([k, o[k]]);}return a;})(prelude)

var reserved = [0xa000000,0xb000000,0x7f000000,0x80000000,0xa9fe0000,0xa9ff0000,0xac100000,0xac200000,0xc0a80000,0xc0a90000,0xf0000000,0xfa000000]

var blacklist = {"10.10.10.10":1,"127.0.0.2":1,"243.185.187.3":1,"243.185.187.30":1,"249.129.46.48":1,"253.157.14.165":1,"255.255.255.255":1,"101.226.10.8":1,"103.56.16.112":1,"110.249.209.42":1,"111.11.208.2":1,"111.175.221.58":1,"112.132.230.179":1,"113.11.194.190":1,"113.12.83.4":1,"113.12.83.5":1,"114.112.163.232":1,"114.112.163.254":1,"116.89.243.8":1,"120.192.83.163":1,"120.209.138.64":1,"123.125.81.12":1,"123.126.249.238":1,"123.129.254.11":1,"123.129.254.12":1,"123.129.254.13":1,"123.129.254.14":1,"123.129.254.15":1,"123.129.254.16":1,"123.129.254.17":1,"123.129.254.18":1,"123.129.254.19":1,"124.232.132.94":1,"125.211.213.130":1,"125.211.213.131":1,"125.211.213.132":1,"125.211.213.133":1,"125.211.213.134":1,"125.76.239.244":1,"125.76.239.245":1,"180.153.103.224":1,"180.168.41.175":1,"183.207.232.253":1,"183.221.242.172":1,"183.221.250.11":1,"183.224.40.24":1,"202.100.220.54":1,"202.100.68.117":1,"202.102.110.203":1,"202.102.110.204":1,"202.102.110.205":1,"202.106.1.2":1,"202.106.199.34":1,"202.106.199.35":1,"202.106.199.36":1,"202.106.199.37":1,"202.106.199.38":1,"202.98.24.121":1,"202.98.24.122":1,"202.98.24.123":1,"202.98.24.124":1,"202.98.24.125":1,"202.99.254.230":1,"202.99.254.231":1,"202.99.254.232":1,"211.136.113.1":1,"211.137.130.101":1,"211.138.102.198":1,"211.138.34.204":1,"211.138.74.132":1,"211.139.136.73":1,"211.94.66.147":1,"211.98.70.195":1,"211.98.70.226":1,"211.98.70.227":1,"211.98.71.195":1,"218.28.144.36":1,"218.28.144.37":1,"218.28.144.38":1,"218.28.144.39":1,"218.28.144.40":1,"218.28.144.41":1,"218.28.144.42":1,"218.30.64.194":1,"218.68.250.117":1,"218.68.250.118":1,"218.68.250.119":1,"218.68.250.120":1,"218.68.250.121":1,"218.93.250.18":1,"219.146.13.36":1,"220.165.8.172":1,"220.165.8.174":1,"220.250.64.18":1,"220.250.64.19":1,"220.250.64.20":1,"220.250.64.21":1,"220.250.64.22":1,"220.250.64.225":1,"220.250.64.226":1,"220.250.64.227":1,"220.250.64.228":1,"220.250.64.23":1,"220.250.64.24":1,"220.250.64.25":1,"220.250.64.26":1,"220.250.64.27":1,"220.250.64.28":1,"220.250.64.29":1,"220.250.64.30":1,"221.179.46.190":1,"221.179.46.194":1,"221.192.153.41":1,"221.192.153.42":1,"221.192.153.43":1,"221.192.153.44":1,"221.192.153.45":1,"221.192.153.46":1,"221.192.153.49":1,"221.204.244.36":1,"221.204.244.37":1,"221.204.244.38":1,"221.204.244.39":1,"221.204.244.40":1,"221.204.244.41":1,"221.8.69.27":1,"222.221.5.204":1,"222.221.5.252":1,"222.221.5.253":1,"223.82.248.117":1,"42.123.125.237":1,"60.19.29.21":1,"60.19.29.22":1,"60.19.29.23":1,"60.19.29.24":1,"60.19.29.25":1,"60.19.29.26":1,"60.19.29.27":1,"60.191.124.236":1,"60.191.124.252":1,"61.131.208.210":1,"61.131.208.211":1,"61.139.8.101":1,"61.139.8.102":1,"61.139.8.103":1,"61.139.8.104":1,"61.183.1.186":1,"61.191.206.4":1,"61.54.28.6":1}

// see https://github.com/misakaio/chnroutes2
var iplist = [
	{{- range (fetch "" 15 86400 "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2/chnroutes.txt").Lines -}}
	{{ with $a := split "/" . }}{{ with $b := ipInt $a._0 }}{{ $b }},{{ sub 32 $a._1 }},{{ end }}{{ end }}{{ end -}}
]

function FindProxyForURL(_, host) {
	for ([k, v] of wildcard)
		if (shExpMatch(host, k))
			return v ? (typeof v === 'string' ? v : proxy) : direct

	var i
	var tld = host
	do {
		if ((v = prelude[tld]) !== undefined)
			return v ? (typeof v === 'string' ? v : proxy) : direct
		i = tld.indexOf('.') + 1
		tld = tld.slice(i)
	} while (i >= 1)

	var ipaddr = dnsResolve(host)
	if (!ipaddr)
		return proxy

	var b = ipaddr.split('.')
	var ip = (((b[0]*256+(+b[1]))*256+(+b[2]))*256)+(+b[3])

	var intranet = false
	for (i = 0; i < reserved.length/2; i++)
		if (ip >= reserved[2 * i] && ip < reserved[2 * i + 1]) {
			intranet = true
			break
		}

	var blacklisted = blacklist[ipaddr] !== undefined

	if (blacklisted && !intranet)
		return proxy

	if (((blacklisted && intranet) || ip === 0x7f000001))
		if (tld !== host && tld !== 'internal' && tld !== 'local' && tld !== 'localhost' && tld !== 'test')
			return proxy

	if (intranet || ip == 0)
		return direct

	var n = iplist.length
	i = 0
	while (i < n - 2) {
		m = ((i + n) >> 1) & 0xfffe
		v = iplist[m]
		if (v <= ip) {
			i = m
		} else {
			n = m
		}
	}

	if (i < iplist.length && ip < iplist[i] + (1<<iplist[i+1]))
		return direct

	return proxy
}
