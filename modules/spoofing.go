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

	if isNotSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Not spoofable."}
	}
	if isOrganizationalSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only organizational domain spoofing is possible. Subdomain spoofing is not possible."}
	}
	if isSubdomainAndOrganizationalSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing is possible."}
	}
	if isSubdomainSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only subdomain spoofing is possible. Organizational domain spoofing is not possible."}
	}
	if isOrganizationalSpoofingMayBePossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only organizational domain spoofing MAY be possible (Mailbox dependant). Subdomain spoofing is not possible."}
	}
	if isOrganizationalSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only organizational domain spoofing MAY be possible (Mailbox dependant). Subdomain spoofing is not possible."}
	}
	if isSubdomainAndOrganizationalSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing MAY be possible (Mailbox dependant)."}
	}
	if isSubdomainSpoofingISAndOrganizationalMayBePossible(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Subdomain spoofing IS possible & organizational domain spoofing MAY be possible."}
	}
	if isSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing MAY be possible (Mailbox dependant)."}
	}
	if isSubdomainSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Only subdomain spoofing may be possible (Mailbox dependant). Organizational domain spoofing is not possible."}
	}
	if isSpoofable(spfRecord, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing is possible."}
	}
	if isSpoofableTooManyLookups(dnsQueryCount, dmarcPolicy, aspf, subPolicy) {
		return SpoofingResult{Spoofability: "Spoofing is possible."}
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
		{"-all", "reject", "", ""},
		{"-all", "reject", "r", ""},
		{"-all", "reject", "s", ""},
		{"-all", "quarantine", "", ""},
		{"-all", "quarantine", "r", ""},
		{"-all", "quarantine", "s", ""},
		{"-all", "none", "s", ""},
		{"-all", "reject", "r", "reject"},
		{"-all", "none", "s", "reject"},
		{"-all", "reject", "s", "quarantine"},
		{"-all", "none", "s", "quarantine"},
		{"-all", "quarantine", "s", "quarantine"},
		{"-all", "quarantine", "r", "reject"},
		{"-all", "quarantine", "r", "quarantine"},
		{"-all", "reject", "s", "none"},
		{"-all", "reject", "s", "reject"},
		{"-all", "reject", "r", "quarantine"},
		{"-all", "quarantine", "s", "reject"},
		{"-all", "quarantine", "s", "none"},
		{"-all", "reject", "s", "none"},
		{"-all", "quarantine", "", "quarantine"},
		{"-all", "reject", "", "quarantine"},
		{"-all", "reject", "", "reject"},
		{"-all", "quarantine", "", "reject"},
		{"?all", "reject", "", ""},
		{"?all", "quarantine", "", ""},
		{"?all", "reject", "r", ""},
		{"?all", "reject", "s", ""},
		{"?all", "quarantine", "r", ""},
		{"?all", "quarantine", "s", ""},
		{"?all", "reject", "r", "quarantine"},
		{"?all", "reject", "r", "reject"},
		{"?all", "quarantine", "s", "reject"},
		{"?all", "reject", "s", "reject"},
		{"?all", "quarantine", "s", "quarantine"},
		{"?all", "quarantine", "r", "quarantine"},
		{"?all", "quarantine", "r", "reject"},
		{"?all", "reject", "s", "quarantine"},
		{"?all", "quarantine", "", "quarantine"},
		{"?all", "reject", "", "quarantine"},
		{"?all", "none", "", "quarantine"},
		{"?all", "reject", "", "reject"},
		{"?all", "quarantine", "", "reject"},
		{"~all", "reject", "", ""},
		{"~all", "quarantine", "", ""},
		{"~all", "reject", "r", ""},
		{"~all", "reject", "s", ""},
		{"~all", "quarantine", "r", ""},
		{"~all", "quarantine", "s", ""},
		{"~all", "quarantine", "s", "quarantine"},
		{"~all", "reject", "s", "quarantine"},
		{"~all", "reject", "r", "reject"},
		{"~all", "reject", "r", "quarantine"},
		{"~all", "quarantine", "r", "quarantine"},
		{"~all", "quarantine", "r", "reject"},
		{"~all", "reject", "s", "reject"},
		{"~all", "quarantine", "s", "reject"},
		{"~all", "quarantine", "", "quarantine"},
		{"~all", "reject", "", "quarantine"},
		{"~all", "reject", "", "reject"},
		{"~all", "quarantine", "", "reject"},
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
		{"~all", "quarantine", "r", "none"},
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
		{"?all", "none", "r", ""},
		{"?all", "", "", ""},
		{"~all", "none", "", ""},
		{"~all", "none", "r", ""},
		{"~all", "none", "s", ""},
		{"~all", "", "", ""},
		{"", "", "", ""},
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
		{"-all", "none", "r", "quarantine"},
		{"-all", "none", "r", "reject"},
		{"~all", "none", "s", "reject"},
		{"~all", "none", "s", "quarantine"},
		{"~all", "none", "r", "reject"},
		{"~all", "none", "r", "quarantine"},
		{"~all", "none", "", "quarantine"},
		{"~all", "none", "", "reject"},
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
		{"-all", "reject", "r", "none"},
		{"-all", "none", "r", "none"},
		{"-all", "quarantine", "r", "none"},
		{"-all", "none", "s", "none"},
		{"-all", "quarantine", "", "none"},
		{"-all", "reject", "", "none"},
		{"~all", "reject", "r", "none"},
		{"~all", "reject", "s", "none"},
		{"~all", "quarantine", "s", "none"},
		{"~all", "quarantine", "", "none"},
		{"~all", "reject", "", "none"},
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

func isSubdomainAndOrganizationalSpoofingPossible(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	subdomainAndOrganizationalConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{
		{"?all", "none", "r", "none"},
		{"~all", "none", "r", "none"},
		{"~all", "none", "s", "none"},
		{"~all", "none", "", "none"},
	}
	for _, condition := range subdomainAndOrganizationalConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func isOrganizationalSpoofingMayBePossible(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	mayBePossibleConditions := []struct {
		spf    string
		dmarc  string
		aspf   string
		subPol string
	}{
		{"-all", "none", "", "quarantine"},
		{"-all", "none", "", "reject"},
	}
	for _, condition := range mayBePossibleConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.subPol != "" && subPolicy == condition.subPol) || condition.subPol == "") {
			return true
		}
	}
	return false
}

func isOrganizationalSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	mayBePossibleMailboxDependantConditions := []struct {
		spf   string
		dmarc string
		aspf  string
		sub   string
	}{
		{"?all", "none", "s", "quarantine"},
		{"?all", "none", "r", "reject"},
		{"?all", "none", "s", "reject"},
		{"?all", "none", "r", "quarantine"},
		{"?all", "none", "", "reject"},
	}
	for _, condition := range mayBePossibleMailboxDependantConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.sub != "" && subPolicy == condition.sub) || condition.sub == "") {
			return true
		}
	}
	return false
}

func isSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	mayBePossibleMailboxDependantConditions := []struct {
		spf   string
		dmarc string
		aspf  string
		sub   string
	}{
		{"-all", "none", "", ""},
		{"-all", "none", "r", ""},
		{"?all", "none", "", ""},
		{"?all", "none", "s", ""},
	}
	for _, condition := range mayBePossibleMailboxDependantConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") {
			return true
		}
	}
	return false
}

func isSubdomainSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	mayBePossibleMailboxDependantConditions := []struct {
		spf   string
		dmarc string
		aspf  string
		sub   string
	}{
		{"?all", "quarantine", "r", "none"},
		{"?all", "reject", "s", "none"},
		{"?all", "reject", "r", "none"},
		{"?all", "quarantine", "s", "none"},
		{"?all", "quarantine", "", "none"},
		{"?all", "reject", "", "none"},
	}
	for _, condition := range mayBePossibleMailboxDependantConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.sub != "" && subPolicy == condition.sub) || condition.sub == "") {
			return true
		}
	}
	return false
}

func isSubdomainAndOrganizationalSpoofingMayBePossibleMailboxDependant(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	mayBePossibleConditions := []struct {
		spf   string
		dmarc string
		aspf  string
		sub   string
	}{
		{"?all", "none", "s", "none"},
		{"?all", "none", "", "none"},
	}
	for _, condition := range mayBePossibleConditions {
		if spfRecord == condition.spf &&
			dmarcPolicy == condition.dmarc &&
			((condition.aspf != "" && aspf == condition.aspf) || condition.aspf == "") &&
			((condition.sub != "" && subPolicy == condition.sub) || condition.sub == "") {
			return true
		}
	}
	return false
}

func isSubdomainSpoofingISAndOrganizationalMayBePossible(spfRecord, dmarcPolicy, aspf, subPolicy string) bool {
	return spfRecord == "-all" && dmarcPolicy == "none" && aspf == "" && subPolicy == "none"
}

func (s *Spoofing) String() string {
	return fmt.Sprintf("Domínio: %s\nSPF: %s\nDMARC: %s\nAspf: %s\nSubdomainPolicy: %s\nSpoofability: %s\n",
		s.Domain, s.SPFAll, s.Policy, s.ASPF, s.SubdomainPolicy, s.Spoofability)
}
