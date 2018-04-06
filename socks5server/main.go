package main

import (
	"time"
	"net"
	"errors"
	"log"
	"flag"
	"github.com/cyilin/gosocks"
	"github.com/miekg/dns"
	"sync"
	"strings"
)

var (
	ListenAddress   string
	InterfaceName   string
	DnsServer       string
	Debug           bool
	IPv4            bool
	IPv6            bool
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
	DnsCache        DnsCacheMap
	SourceIP        net.IP
	ForwardTo       string
)

type DnsCacheMap struct {
	sync.Map
}
type DnsRecord struct {
	exp    time.Time
	record dns.RR
}

func main() {
	flag.StringVar(&ListenAddress, "listen", "[::]:1080", "Listen address")
	flag.StringVar(&InterfaceName, "interface", "", "Use network interface for outbound traffic")
	flag.BoolVar(&Debug, "debug", false, "Show debug info")
	flag.BoolVar(&IPv6, "6", false, "Use IPv6 address")
	flag.BoolVar(&IPv4, "4", true, "Use IPv4 address")
	flag.StringVar(&DnsServer, "dns", "", "DNS server")
	flag.StringVar(&ForwardTo, "forward", "", "Forward request to target host:port")
	flag.Parse()
	if IPv6 {
		IPv4 = false
	} else {
		IPv6 = false
	}
	DnsCache = DnsCacheMap{}
	server := gosocks.NewBasicServer(ListenAddress, time.Minute)
	server.AllowConnect = true
	server.AllowBind = false
	server.AllowUDPAssociate = false
	if InterfaceName != "" {
		server.Dial = newDialFromIP
		ticker := time.NewTicker(time.Second * 15)
		go func() {
			for range ticker.C {
				updateSourceIP()
			}
		}()
		updateSourceIP()
	} else {
		server.Dial = net.DialTimeout
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func updateSourceIP() {
	ip, err := GetIPByInterfaceName(InterfaceName)
	if err != nil {
		log.Printf(err.Error())
	} else {
		if !ip.Equal(SourceIP) {
			log.Printf("source ip: " + ip.String())
			SourceIP = ip
		}
	}
}

func newDialFromIP(network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: SourceIP},
		Timeout:   timeout,
		DualStack: false,
	}
	if (ForwardTo != "") {
		return d.Dial(network, ForwardTo)
	}

	if DnsServer != "" {
		host, port, err := net.SplitHostPort(address)
		if err == nil {
			ip := net.ParseIP(host)
			if ip == nil { // domain
				var err error = nil
				if IPv4 {
					ip, err = LookupHostname(host, dns.TypeA)
				} else {
					ip, err = LookupHostname(host, dns.TypeAAAA)
				}
				if err == nil {
					if IPv4 {
						return d.Dial(network, ip.String()+":"+string(port))
					} else {
						return d.Dial(network, "["+ip.String()+"]:"+string(port))
					}
				} else {
					return nil, err
				}
			}
		}
		// IPv4 or IPv6 address
	}
	return d.Dial(network, address)
}

func GetIPByInterfaceName(name string) (net.IP, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err == nil {
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				if IPv4 && ip.To4().Equal(ip) {
					return ip, nil
				} else if IPv6 && ip.To16().Equal(ip) && ip.To4() == nil {
					return ip, nil
				}
			}
		}
	}
	return nil, errors.New("No IP address available.")
}
func LookupHostname(host string, rtype uint16) (net.IP, error) {
	if Debug {
		log.Printf("lookup: " + host)
	}
	cache, exist := DnsCache.Load(host)
	if exist && cache.(DnsRecord).exp.After(time.Now()) {
		if Debug {
			log.Printf("cached: " + cache.(DnsRecord).record.String() + " " + cache.(DnsRecord).exp.String())
		}
		return getIPFromRecord(cache.(DnsRecord).record, rtype), nil
	}
	scheme, dnsHost := "udp", DnsServer
	if strings.Contains(DnsServer, "://") {
		s := strings.Split(DnsServer, "://")
		if len(s) == 2 {
			scheme = s[0]
			dnsHost = s[1]
		} else {
			return nil, errors.New("Invalid DNS address")
		}
	}
	client := dns.Client{Net: scheme}
	dnsIp := net.ParseIP(dnsHost)
	if dnsIp == nil || !dnsIp.IsLoopback() {
		client.Dialer = &net.Dialer{DualStack: false}
		if strings.Contains(scheme, "tcp") {
			client.Dialer.LocalAddr = &net.TCPAddr{IP: SourceIP}
		} else {
			client.Dialer.LocalAddr = &net.UDPAddr{IP: SourceIP}
		}
	}
	msg := dns.Msg{}
	if IPv4 {
		msg.SetQuestion(host+".", dns.TypeA)
	} else {
		msg.SetQuestion(host+".", dns.TypeAAAA)
	}
	if (IPv4 && !strings.Contains(dnsHost, ":")) || (IPv6 && !strings.Contains(dnsHost, "]:")) {
		dnsHost = dnsHost + ":53"
	}
	result, duration, err := client.Exchange(&msg, dnsHost)
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}
	if Debug {
		log.Printf(host + " " + duration.String())
	}
	var ipAddress net.IP = nil
	if len(result.Answer) != 0 {
		for _, answer := range result.Answer {
			if Debug {
				log.Printf(answer.String())
			}
			if rtype == dns.TypeA && answer.Header().Rrtype == dns.TypeA {
				record := answer.(*dns.A)
				DnsCache.Store(host, DnsRecord{record: answer, exp: time.Now().Add(time.Second * time.Duration(record.Header().Ttl))})
				ipAddress = record.A
				break
			} else if rtype == dns.TypeAAAA && answer.Header().Rrtype == dns.TypeAAAA {
				record := answer.(*dns.AAAA)
				DnsCache.Store(host, DnsRecord{record: answer, exp: time.Now().Add(time.Second * time.Duration(record.Header().Ttl))})
				ipAddress = record.AAAA
				break
			}
		}
	}
	if Debug && ipAddress != nil {
		log.Printf("dns query success: %s->%s", host, ipAddress)
	}
	if ipAddress == nil {
		return nil, errors.New("host " + host + " not found")
	}
	return ipAddress, nil
}
func getIPFromRecord(rr dns.RR, rtype uint16) net.IP {
	if rtype == dns.TypeA {
		record := rr.(*dns.A)
		return record.A
	} else {
		record := rr.(*dns.AAAA)
		return record.AAAA
	}
}
