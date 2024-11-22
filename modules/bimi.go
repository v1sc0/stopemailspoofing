// modules/bimi.go
package modules

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type BIMI struct {
	Domain     string
	DNSServer  string
	BIMIRecord string
	Version    string
	Location   string
	Authority  string
}

func NovoBIMI(dominio, dnsServer string) *BIMI {
	bimi := &BIMI{Domain: dominio, DNSServer: dnsServer}
	bimi.ObterBIMIRecord()
	return bimi
}

func (b *BIMI) ObterBIMIRecord() {
	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("default._bimi.%s.", b.Domain), dns.TypeTXT)
	in, err := dns.Exchange(m, b.DNSServer+":53")

	if err != nil || len(in.Answer) == 0 {
		b.BIMIRecord = "BIMI não encontrado"
		return
	}

	for _, ans := range in.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			record := strings.Join(txt.Txt, "")
			if strings.Contains(record, "v=BIMI") {
				b.BIMIRecord = record
				b.Version = b.ExtrairVersao()
				b.Location = b.ExtrairLocalizacao()
				b.Authority = b.ExtrairAutoridade()
				return
			}
		}
	}

	b.BIMIRecord = "BIMI não encontrado"
}

func (b *BIMI) ExtrairVersao() string {
	if strings.Contains(b.BIMIRecord, "v=") {
		parts := strings.Split(b.BIMIRecord, "v=")
		return strings.Split(parts[1], ";")[0]
	}
	return ""
}

func (b *BIMI) ExtrairLocalizacao() string {
	if strings.Contains(b.BIMIRecord, "l=") {
		parts := strings.Split(b.BIMIRecord, "l=")
		return strings.Split(parts[1], ";")[0]
	}
	return ""
}

func (b *BIMI) ExtrairAutoridade() string {
	if strings.Contains(b.BIMIRecord, "a=") {
		parts := strings.Split(b.BIMIRecord, "a=")
		return strings.Split(parts[1], ";")[0]
	}
	return ""
}

func (b *BIMI) String() string {
	return fmt.Sprintf("BIMI Record: %s\nVersion: %s\nLocation: %s\nAuthority: %s\n",
		b.BIMIRecord, b.Version, b.Location, b.Authority)
}
