// This file has been adapted from https://github.com/norouter/norouter/blob/v0.6.4/pkg/agent/dns/dns.go

package dns

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Truncate for avoiding "Parse error" from `busybox nslookup`
// https://github.com/lima-vm/lima/issues/380
const truncateSize = 512

var defaultFallbackIPs = []string{"8.8.8.8", "1.1.1.1"}

type ServerOptions struct {
	Address         string
	TCPPort         int
	UDPPort         int
	IPv6            bool
	StaticHosts     map[string]string
	UpstreamServers []string
	Listener        net.Listener
}

type Handler struct {
	clientConfig *dns.ClientConfig
	clients      []*dns.Client
	IPv6         bool
	cname        map[string]string
	ip           map[string]net.IP
}

type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

func Cname(host string) string {
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	return host
}

func (s *Server) Shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func newStaticClientConfig(ips []string) (*dns.ClientConfig, error) {
	s := ``
	for _, ip := range ips {
		s += fmt.Sprintf("nameserver %s\n", ip)
	}
	r := strings.NewReader(s)
	return dns.ClientConfigFromReader(r)
}

func newHandler(IPv6 bool, hosts map[string]string, upstreamServers []string) (dns.Handler, error) {
	var cc *dns.ClientConfig
	var err error
	if len(upstreamServers) == 0 {
		if runtime.GOOS != "windows" {
			cc, err = dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				logrus.WithError(err).Warnf("failed to detect system DNS, falling back to %v", defaultFallbackIPs)
				cc, err = newStaticClientConfig(defaultFallbackIPs)
				if err != nil {
					return nil, err
				}
			}
		} else {
			// For windows, the only fallback addresses are defaultFallbackIPs
			// since there is no /etc/resolv.conf
			cc, err = newStaticClientConfig(defaultFallbackIPs)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if cc, err = newStaticClientConfig(upstreamServers); err != nil{
			if cc, err = newStaticClientConfig(defaultFallbackIPs); err != nil{
				return nil, err
			}
		}
	}

	clients := []*dns.Client{
		{}, // UDP
		{Net: "tcp"},
	}
	h := &Handler{
		clientConfig: cc,
		clients:      clients,
		IPv6:         IPv6,
		cname:        make(map[string]string),
		ip:           make(map[string]net.IP),
	}
	for host, address := range hosts {
		if ip := net.ParseIP(address); ip != nil {
			h.ip[Cname(host)] = ip
		} else {
			h.cname[Cname(host)] = Cname(address)
		}
	}
	return h, nil
}

func (h *Handler) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	var (
		reply   dns.Msg
		handled bool
	)
	reply.SetReply(req)
	for _, q := range req.Question {
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: q.Qtype,
			Class:  q.Qclass,
			Ttl:    5,
		}
		switch q.Qtype {
		case dns.TypeAAAA:
			if !h.IPv6 {
				handled = true
				break
			}
			fallthrough
		case dns.TypeCNAME, dns.TypeA:
			cname := q.Name
			seen := make(map[string]bool)
			for {
				// break cyclic definition
				if seen[cname] {
					break
				}
				if _, ok := h.cname[cname]; ok {
					seen[cname] = true
					cname = h.cname[cname]
					continue
				}
				break
			}
			var err error
			if _, ok := h.ip[cname]; !ok {
				cname, err = net.LookupCNAME(cname)
				if err != nil {
					break
				}
			}
			if cname != "" && cname != q.Name {
				hdr.Rrtype = dns.TypeCNAME
				a := &dns.CNAME{
					Hdr:    hdr,
					Target: cname,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
			if q.Qtype == dns.TypeCNAME {
				break
			}
			hdr.Name = cname
			var addrs []net.IP
			if _, ok := h.ip[cname]; ok {
				addrs = []net.IP{h.ip[cname]}
				err = nil
			} else {
				addrs, err = net.LookupIP(cname)
			}
			if err == nil && len(addrs) > 0 {
				for _, ip := range addrs {
					var a dns.RR
					ipv6 := ip.To4() == nil
					if q.Qtype == dns.TypeA && !ipv6 {
						hdr.Rrtype = dns.TypeA
						a = &dns.A{
							Hdr: hdr,
							A:   ip.To4(),
						}
					} else if q.Qtype == dns.TypeAAAA && ipv6 {
						hdr.Rrtype = dns.TypeAAAA
						a = &dns.AAAA{
							Hdr:  hdr,
							AAAA: ip.To16(),
						}
					} else {
						continue
					}
					reply.Answer = append(reply.Answer, a)
					handled = true
				}
			}
		case dns.TypeTXT:
			txt, err := net.LookupTXT(q.Name)
			if err == nil && len(txt) > 0 {
				a := &dns.TXT{
					Hdr: hdr,
					Txt: txt,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		case dns.TypeNS:
			ns, err := net.LookupNS(q.Name)
			if err == nil && len(ns) > 0 {
				for _, s := range ns {
					if s.Host != "" {
						a := &dns.NS{
							Hdr: hdr,
							Ns:  s.Host,
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeMX:
			mx, err := net.LookupMX(q.Name)
			if err == nil && len(mx) > 0 {
				for _, s := range mx {
					if s.Host != "" {
						a := &dns.MX{
							Hdr:        hdr,
							Mx:         s.Host,
							Preference: s.Pref,
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeSRV:
			_, addrs, err := net.LookupSRV("", "", q.Name)
			if err == nil {
				hdr.Rrtype = dns.TypeSRV
				for _, addr := range addrs {
					a := &dns.SRV{
						Hdr:      hdr,
						Target:   addr.Target,
						Port:     addr.Port,
						Priority: addr.Priority,
						Weight:   addr.Weight,
					}
					reply.Answer = append(reply.Answer, a)
					handled = true
				}
			}
		}
	}
	if handled {
		reply.Truncate(truncateSize)
		_ = w.WriteMsg(&reply)
		return
	}
	h.handleDefault(w, req)
}

func (h *Handler) handleDefault(w dns.ResponseWriter, req *dns.Msg) {
	for _, client := range h.clients {
		for _, srv := range h.clientConfig.Servers {
			addr := fmt.Sprintf("%s:%s", srv, h.clientConfig.Port)
			reply, _, err := client.Exchange(req, addr)
			if err == nil {
				reply.Truncate(truncateSize)
				_ = w.WriteMsg(reply)
				return
			}
		}
	}
	var reply dns.Msg
	reply.SetReply(req)
	reply.Truncate(truncateSize)
	_ = w.WriteMsg(&reply)
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	switch req.Opcode {
	case dns.OpcodeQuery:
		h.handleQuery(w, req)
	default:
		h.handleDefault(w, req)
	}
}

// StartWithListener always starts the name server with a TCP listener
// UDP PacketConn is not activated since the underlying AF_SOCK does not support UDP
func StartWithListener(opts *ServerOptions) (*Server, error) {
	h, err := newHandler(opts.IPv6, opts.StaticHosts, opts.UpstreamServers)
	if err != nil {
		return nil, err
	}
	server := &Server{}
	server.tcp = &dns.Server{Net: "tcp", Listener: opts.Listener, Handler: h}
	go func() {
		if e := server.tcp.ActivateAndServe(); e != nil {
			panic(e)
		}
	}()
	return server, nil
}

func Start(opts *ServerOptions) (*Server, error) {
	h, err := newHandler(opts.IPv6, opts.StaticHosts, opts.UpstreamServers)
	if err != nil {
		return nil, err
	}
	server := &Server{}
	if opts.UDPPort > 0 {
		addr := fmt.Sprintf("%s:%d", opts.Address, opts.UDPPort)
		s := &dns.Server{Net: "udp", Addr: addr, Handler: h}
		server.udp = s
		go func() {
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	if opts.TCPPort > 0 {
		addr := fmt.Sprintf("%s:%d", opts.Address, opts.TCPPort)
		s := &dns.Server{Net: "tcp", Addr: addr, Handler: h}
		server.tcp = s
		go func() {
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	return server, nil
}
