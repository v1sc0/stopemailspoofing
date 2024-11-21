package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type DMARC struct {
	Domain           string
	DNSServer        string
	DMARCRecord      string
	Policy           string
	Pct              string
	ASPF             string
	SubdomainPolicy  string
	ForensicReports  string
	AggregateReports string
}

func NovoDMARC(dominio, dnsServer string) *DMARC {
	dmarc := &DMARC{Domain: dominio, DNSServer: dnsServer}
	dmarc.ObterDMARCRecord()

	if dmarc.DMARCRecord == "" && isSubdomain(dominio) {
		parentDomain, err := getOrganizationalDomain(dominio)
		if err != nil {
			fmt.Printf("Error in obtaining organizational domain for %s: %v\n", dominio, err)
		} else {
			fmt.Printf("DMARC not found for %s.\nAttempting organizational domain: %s\n\n", dominio, parentDomain)
			dmarc.Domain = parentDomain
			dmarc.ObterDMARCRecord()
		}
	}

	if dmarc.DMARCRecord != "" {
		dmarc.Policy = dmarc.ObterPolicy()
		dmarc.Pct = dmarc.ObterPct()
		dmarc.ASPF = dmarc.ObterASPF()
		dmarc.SubdomainPolicy = dmarc.ObterSubdomainPolicy()
		dmarc.ForensicReports = dmarc.ObterForensicReports()
		dmarc.AggregateReports = dmarc.ObterAggregateReports()
	}
	return dmarc
}

func (d *DMARC) ObterDMARCRecord() {
	dmarcDomain := fmt.Sprintf("_dmarc.%s.", d.Domain)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		fmt.Printf("Error querying DNS for %s: %v\n", d.Domain, err)
		return
	}

	for _, record := range records {
		if strings.Contains(record, "DMARC1") {
			d.DMARCRecord = record
			return
		}
	}

	fmt.Printf("DMARC record not found for: %s\n", d.Domain)
}

func isSubdomain(domain string) bool {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false
	}
	return domain != eTLDPlusOne
}

func getOrganizationalDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

func (d *DMARC) ObterPolicy() string {
	if strings.Contains(d.DMARCRecord, "p=") {
		return strings.Split(strings.Split(d.DMARCRecord, "p=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) ObterPct() string {
	if strings.Contains(d.DMARCRecord, "pct=") {
		return strings.Split(strings.Split(d.DMARCRecord, "pct=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) ObterASPF() string {
	if strings.Contains(d.DMARCRecord, "aspf=") {
		return strings.Split(strings.Split(d.DMARCRecord, "aspf=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) ObterSubdomainPolicy() string {
	if strings.Contains(d.DMARCRecord, "sp=") {
		return strings.Split(strings.Split(d.DMARCRecord, "sp=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) ObterForensicReports() string {
	if strings.Contains(d.DMARCRecord, "ruf=") {
		return strings.Split(strings.Split(d.DMARCRecord, "ruf=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) ObterAggregateReports() string {
	if strings.Contains(d.DMARCRecord, "rua=") {
		return strings.Split(strings.Split(d.DMARCRecord, "rua=")[1], ";")[0]
	}
	return ""
}

func (d *DMARC) String() string {
	return fmt.Sprintf("DMARC Record: %s\nPolicy: %s\nPct: %s\nASPF: %s\nSubdomain Policy: %s\nForensic Reports: %s\nAggregate Reports: %s\n",
		d.DMARCRecord, d.Policy, d.Pct, d.ASPF, d.SubdomainPolicy, d.ForensicReports, d.AggregateReports)
}
