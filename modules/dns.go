// modules/dns.go
package modules

import (
	"fmt"
	"net"
	"net/url"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type DNS struct {
	Domain     string
	SOARecord  string
	DNSServer  string
	MXRecords  []string
	DomainType string
}

func NovoDNS(dominio string) *DNS {
	dnsModule := &DNS{Domain: dominio}
	dnsModule.ObterTipoDominio()
	dnsModule.ObterSOARecord()
	dnsModule.ObterMXRecords()
	return dnsModule
}

func (d *DNS) ObterTipoDominio() {
	parsedURL, err := url.Parse("http://" + d.Domain)
	if err != nil {
		d.DomainType = "unknown"
		return
	}
	hostname := parsedURL.Hostname()

	dominioRegistrado, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		d.DomainType = "unknown"
		return
	}

	if hostname == dominioRegistrado {
		d.DomainType = "domain"
	} else {
		d.DomainType = "subdomain"
	}
}

func (d *DNS) ObterSOARecord() {
	m := new(dns.Msg)
	m.SetQuestion(d.Domain+".", dns.TypeSOA)
	in, err := dns.Exchange(m, "1.1.1.1:53")
	if err != nil || len(in.Answer) == 0 {
		return
	}
	if soa, ok := in.Answer[0].(*dns.SOA); ok {
		d.SOARecord = soa.Ns
		ips, err := net.LookupHost(soa.Ns)
		if err == nil && len(ips) > 0 {
			d.DNSServer = ips[0]
		} else {
			d.DNSServer = "IP Address not found"
		}
	}
}

func (d *DNS) ObterMXRecords() {
	m := new(dns.Msg)
	m.SetQuestion(d.Domain+".", dns.TypeMX)
	in, err := dns.Exchange(m, "1.1.1.1:53")
	if err != nil || len(in.Answer) == 0 {
		return
	}
	for _, ans := range in.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			d.MXRecords = append(d.MXRecords, mx.Mx)
		}
	}
}

func (d *DNS) String() string {
	return fmt.Sprintf("Domain: %s (%s)\nSOA Record: %s\nDNS Server: %s\nMX Records: %v\n",
		d.Domain, d.DomainType, d.SOARecord, d.DNSServer, d.MXRecords)
}
