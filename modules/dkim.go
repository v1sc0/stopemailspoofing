// modules/dkim.go
package modules

import (
	"fmt"
	"regexp"

	"github.com/miekg/dns"
)

type DKIMResult struct {
	Domain     string
	Selector   string
	DKIMFound  string
	DKIMRecord string
}

var defaultSelectors = []string{
	"default", "dkim", "selector", "selector1", "selector2", "s1", "s2", "api", "smtp", "smtpapi", "mail", "m1", "m2", "ms", "mx", "k1", "k2", "google",
	"amazonses", "mandrill", "sparkpost", "mailjet", "sendgrid", "zoho", "office365", "mx", "o365", "postmark", "spf",
	"transmail", "mailgun", "sendinblue", "sendpulse", "campaignmonitor", "constantcontact", "sfmc", "oracle", "smtp1",
	"smtp2", "dmarc", "a1", "b1", "sendy", "gsuite", "gsmtp", "outlook", "smtp-relay", "domainkey", "mta", "cisco",
	"mailchimp", "hubspot", "dynect", "ses", "alt1", "alt2", "mta-sts", "notify", "primary", "backup", "campaign",
	"em1", "em2", "feedback", "relay", "route", "transactional", "info", "support", "newsletter", "alerts", "bulletin",
	"webmail", "no-reply", "service", "marketing", "prod", "app", "corp", "a", "b", "c", "d", "send", "user1", "user2",
	"user3", "public", "private", "group1", "group2", "group3", "noreply", "admin", "engage", "engagement", "portal",
	"reports", "events", "alerts1", "alerts2", "feedback1", "feedback2", "analytics", "zimbra",
}

func ValidarDominio(dominio string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	return re.MatchString(dominio)
}

func VerificarDKIM(dominios []string) []DKIMResult {
	var resultados []DKIMResult

	for _, dominio := range dominios {
		if !ValidarDominio(dominio) {
			resultados = append(resultados, DKIMResult{Domain: dominio, DKIMFound: "Domínio inválido"})
			continue
		}

		dkimEncontrado := false

		for _, seletor := range defaultSelectors {
			dkimQuery := fmt.Sprintf("%s._domainkey.%s", seletor, dominio)
			resultado := DKIMResult{Domain: dominio, Selector: seletor, DKIMFound: "NÃO"}

			m := new(dns.Msg)
			m.SetQuestion(dkimQuery+".", dns.TypeTXT)
			in, err := dns.Exchange(m, "1.1.1.1:53")

			if err != nil || len(in.Answer) == 0 {
				resultado.DKIMFound = "Sem registros TXT"
			} else {
				for _, ans := range in.Answer {
					if txt, ok := ans.(*dns.TXT); ok {
						resultado.DKIMFound = "SIM"
						resultado.DKIMRecord = fmt.Sprintf("%s", txt.Txt)
						dkimEncontrado = true
						break
					}
				}
			}

			if dkimEncontrado {
				resultados = append(resultados, resultado)
				break
			}
		}

		if !dkimEncontrado {
			resultados = append(resultados, DKIMResult{Domain: dominio, DKIMFound: "DKIM não encontrado"})
		}
	}

	return resultados
}
