package modules

import (
	"fmt"
)

type Spoofing struct {
	Domain          string
	SPFAll          string
	Policy          string
	ASPF            string
	SubdomainPolicy string
	Spoofability    string
}

type SpoofingResult struct {
	Spoofability string
}

func NovoSpoofing(domain, spfAll, dmarcPolicy, aspf, subPolicy, dmarcRecord string) *Spoofing {
	spoof := &Spoofing{
		Domain:          domain,
		SPFAll:          spfAll,
		Policy:          dmarcPolicy,
		ASPF:            aspf,
		SubdomainPolicy: subPolicy,
	}
	spoof.Spoofability = CheckSpoofing(spfAll, dmarcPolicy, aspf, subPolicy, dmarcRecord).Spoofability
	return spoof
}

func CheckSpoofing(spfRecord, dmarcPolicy, aspf, subPolicy, dnsQueryCount string) SpoofingResult {

	if isSubdomainSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only subdomain spoofing is possible. Organizational domain spoofing is not possible."}
	}
	if isOrganizationalSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only organizational domain spoofing is possible. Subdomain spoofing is not possible."}
	}
	if isSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Organizational domain spoofing and subdomain spoofing are possible."}
	}
	if isSpoofableTooManyLookups(dnsQueryCount, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Organizational domain spoofing and subdomain spoofing are possible."}
	}
	if isNotSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing is not possible."}
	}
	return SpoofingResult{Spoofability: "Unknown condition (Possibly SPOOFABLE due to a syntax error in one or more records)."}
}

func isNotSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	notSpoofableConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{
		{"-all", "quarantine", "", ""},
		{"-all", "quarantine", "", "quarantine"},
		{"-all", "quarantine", "", "reject"},
		{"-all", "quarantine", "r", ""},
		{"-all", "quarantine", "r", "quarantine"},
		{"-all", "quarantine", "r", "reject"},
		{"-all", "quarantine", "s", ""},
		{"-all", "quarantine", "s", "quarantine"},
		{"-all", "quarantine", "s", "reject"},
		{"-all", "reject", "", ""},
		{"-all", "reject", "", "quarantine"},
		{"-all", "reject", "", "reject"},
		{"-all", "reject", "r", ""},
		{"-all", "reject", "r", "quarantine"},
		{"-all", "reject", "r", "reject"},
		{"-all", "reject", "s", ""},
		{"-all", "reject", "s", "quarantine"},
		{"-all", "reject", "s", "reject"},

		{"?all", "quarantine", "", ""},
		{"?all", "quarantine", "", "quarantine"},
		{"?all", "quarantine", "", "reject"},
		{"?all", "quarantine", "r", ""},
		{"?all", "quarantine", "r", "quarantine"},
		{"?all", "quarantine", "r", "reject"},
		{"?all", "quarantine", "s", ""},
		{"?all", "quarantine", "s", "quarantine"},
		{"?all", "quarantine", "s", "reject"},
		{"?all", "reject", "", ""},
		{"?all", "reject", "", "quarantine"},
		{"?all", "reject", "", "reject"},
		{"?all", "reject", "r", ""},
		{"?all", "reject", "r", "quarantine"},
		{"?all", "reject", "r", "reject"},
		{"?all", "reject", "s", ""},
		{"?all", "reject", "s", "quarantine"},
		{"?all", "reject", "s", "reject"},

		{"~all", "quarantine", "", ""},
		{"~all", "quarantine", "", "quarantine"},
		{"~all", "quarantine", "", "reject"},
		{"~all", "quarantine", "r", ""},
		{"~all", "quarantine", "r", "quarantine"},
		{"~all", "quarantine", "r", "reject"},
		{"~all", "quarantine", "s", ""},
		{"~all", "quarantine", "s", "quarantine"},
		{"~all", "quarantine", "s", "reject"},
		{"~all", "reject", "", ""},
		{"~all", "reject", "", "quarantine"},
		{"~all", "reject", "", "reject"},
		{"~all", "reject", "r", ""},
		{"~all", "reject", "r", "quarantine"},
		{"~all", "reject", "r", "reject"},
		{"~all", "reject", "s", ""},
		{"~all", "reject", "s", "quarantine"},
		{"~all", "reject", "s", "reject"},

		{"+all", "quarantine", "", ""},
		{"+all", "quarantine", "", "quarantine"},
		{"+all", "quarantine", "", "reject"},
		{"+all", "quarantine", "r", ""},
		{"+all", "quarantine", "r", "quarantine"},
		{"+all", "quarantine", "r", "reject"},
		{"+all", "quarantine", "s", ""},
		{"+all", "quarantine", "s", "quarantine"},
		{"+all", "quarantine", "s", "reject"},
		{"+all", "reject", "", ""},
		{"+all", "reject", "", "quarantine"},
		{"+all", "reject", "", "reject"},
		{"+all", "reject", "r", ""},
		{"+all", "reject", "r", "quarantine"},
		{"+all", "reject", "r", "reject"},
		{"+all", "reject", "s", ""},
		{"+all", "reject", "s", "quarantine"},
		{"+all", "reject", "s", "reject"},

		{"", "reject", "", ""},
		{"", "quarantine", "", ""},
		{"", "none", "", ""},
		{"", "reject", "r", ""},
		{"", "reject", "s", ""},
		{"", "quarantine", "r", ""},
		{"", "quarantine", "s", ""},
		{"", "none", "r", ""},
		{"", "none", "s", ""},
		{"", "none", "", "none"},
		{"", "quarantine", "", "none"},
		{"", "reject", "", "none"},
		{"", "quarantine", "", "quarantine"},
		{"", "reject", "", "quarantine"},
		{"", "none", "", "quarantine"},
		{"", "none", "", "reject"},
		{"", "reject", "", "reject"},
		{"", "quarantine", "", "reject"},
	}
	for _, condition := range notSpoofableConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func isSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	spoofableConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{

		{"-all", "", "", ""},
		{"-all", "", "", ""},
		{"-all", "", "", "none"},
		{"-all", "", "", "quarantine"},
		{"-all", "", "", "reject"},
		{"-all", "", "r", ""},
		{"-all", "", "r", "none"},
		{"-all", "", "r", "quarantine"},
		{"-all", "", "r", "reject"},
		{"-all", "", "s", ""},
		{"-all", "", "s", "none"},
		{"-all", "", "s", "quarantine"},
		{"-all", "", "s", "reject"},
		{"-all", "none", "", ""},
		{"-all", "none", "", "none"},
		{"-all", "none", "r", ""},
		{"-all", "none", "r", "none"},
		{"-all", "none", "s", ""},
		{"-all", "none", "s", "none"},

		{"?all", "", "", ""},
		{"?all", "", "", ""},
		{"?all", "", "", "none"},
		{"?all", "", "", "quarantine"},
		{"?all", "", "", "reject"},
		{"?all", "", "r", ""},
		{"?all", "", "r", "none"},
		{"?all", "", "r", "quarantine"},
		{"?all", "", "r", "reject"},
		{"?all", "", "s", ""},
		{"?all", "", "s", "none"},
		{"?all", "", "s", "quarantine"},
		{"?all", "", "s", "reject"},
		{"?all", "none", "", ""},
		{"?all", "none", "", "none"},
		{"?all", "none", "r", ""},
		{"?all", "none", "r", "none"},
		{"?all", "none", "s", ""},
		{"?all", "none", "s", "none"},

		{"~all", "", "", ""},
		{"~all", "", "", ""},
		{"~all", "", "", "none"},
		{"~all", "", "", "quarantine"},
		{"~all", "", "", "reject"},
		{"~all", "", "r", ""},
		{"~all", "", "r", "none"},
		{"~all", "", "r", "quarantine"},
		{"~all", "", "r", "reject"},
		{"~all", "", "s", ""},
		{"~all", "", "s", "none"},
		{"~all", "", "s", "quarantine"},
		{"~all", "", "s", "reject"},
		{"~all", "none", "", ""},
		{"~all", "none", "", "none"},
		{"~all", "none", "r", ""},
		{"~all", "none", "r", "none"},
		{"~all", "none", "s", ""},
		{"~all", "none", "s", "none"},

		{"+all", "", "", ""},
		{"+all", "", "", ""},
		{"+all", "", "", "none"},
		{"+all", "", "", "quarantine"},
		{"+all", "", "", "reject"},
		{"+all", "", "r", ""},
		{"+all", "", "r", "none"},
		{"+all", "", "r", "quarantine"},
		{"+all", "", "r", "reject"},
		{"+all", "", "s", ""},
		{"+all", "", "s", "none"},
		{"+all", "", "s", "quarantine"},
		{"+all", "", "s", "reject"},
		{"+all", "none", "", ""},
		{"+all", "none", "", "none"},
		{"+all", "none", "r", ""},
		{"+all", "none", "r", "none"},
		{"+all", "none", "s", ""},
		{"~all", "none", "s", "none"},

		{"", "", "", ""},
		{"", "", "", ""},
		{"", "", "", "none"},
		{"", "", "", "quarantine"},
		{"", "", "", "reject"},
		{"", "", "r", ""},
		{"", "", "r", "none"},
		{"", "", "r", "quarantine"},
		{"", "", "r", "reject"},
		{"", "", "s", ""},
		{"", "", "s", "none"},
		{"", "", "s", "quarantine"},
		{"", "", "s", "reject"},
		{"", "none", "", ""},
		{"", "none", "", "none"},
		{"", "none", "r", ""},
		{"", "none", "r", "none"},
		{"", "none", "s", ""},
		{"", "none", "s", "none"},
	}

	for _, condition := range spoofableConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func isSpoofableTooManyLookups(dnsQueryCount, dmarcPolicy, aspf, subPolicy string) bool {
	return dnsQueryCount == "Too many lookups" && dmarcPolicy == "" && aspf == "" && subPolicy == ""
}

func isOrganizationalSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	organizationalSpoofingConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{
		{"-all", "none", "", "quarantine"},
		{"-all", "none", "", "reject"},
		{"-all", "none", "r", "quarantine"},
		{"-all", "none", "r", "reject"},
		{"-all", "none", "s", "quarantine"},
		{"-all", "none", "s", "reject"},

		{"?all", "none", "", "quarantine"},
		{"?all", "none", "", "reject"},
		{"?all", "none", "r", "quarantine"},
		{"?all", "none", "r", "reject"},
		{"?all", "none", "s", "quarantine"},
		{"?all", "none", "s", "reject"},

		{"~all", "none", "", "quarantine"},
		{"~all", "none", "", "reject"},
		{"~all", "none", "r", "quarantine"},
		{"~all", "none", "r", "reject"},
		{"~all", "none", "s", "quarantine"},
		{"~all", "none", "s", "reject"},

		{"+all", "none", "", "quarantine"},
		{"+all", "none", "", "reject"},
		{"+all", "none", "r", "quarantine"},
		{"+all", "none", "r", "reject"},
		{"+all", "none", "s", "quarantine"},
		{"+all", "none", "s", "reject"},

		{"", "none", "", "quarantine"},
		{"", "none", "", "reject"},
		{"", "none", "r", "quarantine"},
		{"", "none", "r", "reject"},
		{"", "none", "s", "quarantine"},
		{"", "none", "s", "reject"},
	}
	for _, condition := range organizationalSpoofingConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func isSubdomainSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	subdomainSpoofingConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{
		{"-all", "quarantine", "", "none"},
		{"-all", "quarantine", "r", "none"},
		{"-all", "quarantine", "s", "none"},
		{"-all", "reject", "", "none"},
		{"-all", "reject", "r", "none"},
		{"-all", "reject", "s", "none"},

		{"?all", "quarantine", "", "none"},
		{"?all", "quarantine", "r", "none"},
		{"?all", "quarantine", "s", "none"},
		{"?all", "reject", "", "none"},
		{"?all", "reject", "r", "none"},
		{"?all", "reject", "s", "none"},

		{"~all", "quarantine", "", "none"},
		{"~all", "quarantine", "r", "none"},
		{"~all", "quarantine", "s", "none"},
		{"~all", "reject", "", "none"},
		{"~all", "reject", "r", "none"},
		{"~all", "reject", "s", "none"},

		{"+all", "quarantine", "", "none"},
		{"+all", "quarantine", "r", "none"},
		{"+all", "quarantine", "s", "none"},
		{"+all", "reject", "", "none"},
		{"+all", "reject", "r", "none"},
		{"+all", "reject", "s", "none"},

		{"", "quarantine", "", "none"},
		{"", "quarantine", "r", "none"},
		{"", "quarantine", "s", "none"},
		{"", "reject", "", "none"},
		{"", "reject", "r", "none"},
		{"", "reject", "s", "none"},
	}
	for _, condition := range subdomainSpoofingConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func (s *Spoofing) String() string {
	return fmt.Sprintf("Domínio: %s\nSPF: %s\nDMARC: %s\nAspf: %s\nSubdomainPolicy: %s\nSpoofability: %s\n",
		s.Domain, s.SPFAll, s.Policy, s.ASPF, s.SubdomainPolicy, s.Spoofability)
}
