package modules

import (
	"fmt"
	"strings"
)

type Config struct {
	SPF       string
	DMARCP    string
	DMARCASPF string
	DMARCSP   string
}

func Suggestion(spf, dmarcP, dmarcASPF, dmarcSP string) string {
	var suggestions []string

	switch spf {
	case "-all":
		suggestions = append(suggestions, `SPF All Mechanism: Keep it the way it is.`)
	case "~all", "?all":
		suggestions = append(suggestions, `SPF All Mechanism: Replace it by "-all".`)
	case "":
		suggestions = append(suggestions, `SPF All Mechanism: Set SPF record with "-all".`)
	default:
		suggestions = append(suggestions, `SPF All Mechanism: Unexpected SPF value. Review your SPF record.`)
	}

	switch dmarcP {
	case "none":
		suggestions = append(suggestions, `DMARC Policy (p=): Replace it by "p=reject" or "p=quarantine".`)
	case "quarantine":
		suggestions = append(suggestions, `DMARC Policy (p=): Keep it the way it is or replace it by "p=reject".`)
	case "reject":
		suggestions = append(suggestions, `DMARC Policy (p=): Keep it the way it is.`)
	case "":
		suggestions = append(suggestions, `DMARC Policy (p=): Set DMARC record with "p=reject" or "p=quarantine".`)
	default:
		suggestions = append(suggestions, `DMARC Policy (p=): Unexpected DMARC policy. Review your DMARC record.`)
	}

	switch dmarcASPF {
	case "r":
		suggestions = append(suggestions, `DMARC ASPF (aspf=): Keep it the way it is or replace it by "aspf=s".`)
	case "s":
		suggestions = append(suggestions, `DMARC ASPF (aspf=): Keep it the way it is.`)
	case "":
		suggestions = append(suggestions, `DMARC ASPF (aspf=): Add "aspf=s" or "aspf=r".`)
	default:
		suggestions = append(suggestions, `DMARC ASPF (aspf=): Unexpected DMARC 'aspf' value. Review your DMARC record.`)
	}

	switch dmarcSP {
	case "none":
		suggestions = append(suggestions, `DMARC Subdomain Policy (sp=): Replace it by "sp=reject" or "sp=quarantine".`)
	case "quarantine":
		suggestions = append(suggestions, `DMARC Subdomain Policy (sp=): Keep it the way it is or replace it by "sp=reject".`)
	case "reject":
		suggestions = append(suggestions, `DMARC Subdomain Policy (sp=): Keep it the way it is.`)
	case "":
		suggestions = append(suggestions, `DMARC Subdomain Policy (sp=): Add "sp=reject" or "sp=quarantine".`)
	default:
		suggestions = append(suggestions, `DMARC Subdomain Policy (sp=): Unexpected DMARC 'sp' value. Review your DMARC record.`)
	}

	return strings.Join(suggestions, "\n")
}

func main() {
	configs := []Config{
		{"-all", "reject", "r", "quarantine"},
		{"~all", "none", "", "none"},
		{"?all", "quarantine", "s", "reject"},
		{"", "", "", ""},
	}

	for i, config := range configs {
		fmt.Printf("For additional security it is recommended:\n", i+1)
		fmt.Println(Suggestion(config.SPF, config.DMARCP, config.DMARCASPF, config.DMARCSP))
		fmt.Println(strings.Repeat("-", 50))
	}
}
