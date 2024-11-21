// modules/spf.go
package modules

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
)

type SPF struct {
	Domain            string
	SPFRecord         string
	AllMechanism      string
	DNSQueryCount     int
	TooManyDNSQueries bool
}

func NovoSPF(dominio string) *SPF {
	spf := &SPF{Domain: dominio}
	err := spf.ObterSPFRecord()
	if err != nil {
		log.Printf("Erro ao obter registro SPF para %s: %v\n", dominio, err)
		return spf
	}
	if spf.SPFRecord != "" {
		spf.AllMechanism = spf.ObterMecanismoAll()
		spf.DNSQueryCount = spf.ContarConsultasDNS()
		spf.TooManyDNSQueries = spf.DNSQueryCount > 10
	}
	return spf
}

func (s *SPF) ObterSPFRecord() error {
	txtRecords, err := net.LookupTXT(s.Domain)
	if err != nil {
		return fmt.Errorf("erro ao executar consulta DNS para %s: %v", s.Domain, err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			s.SPFRecord = record
			return nil
		}
	}
	return fmt.Errorf("registro SPF não encontrado para %s", s.Domain)
}

func (s *SPF) ObterMecanismoAll() string {
	allMatches := regexp.MustCompile(`[-~+?]all`).FindAllString(s.SPFRecord, -1)
	if len(allMatches) == 1 {
		return allMatches[0]
	} else if len(allMatches) > 1 {
		return "2many"
	}
	return ""
}

func (s *SPF) ContarConsultasDNS() int {
	return s.contarConsultasDNSRecursivo(s.SPFRecord)
}

func (s *SPF) contarConsultasDNSRecursivo(record string) int {
	count := 0
	mechanisms := strings.Fields(record)

	for _, item := range mechanisms {
		if strings.HasPrefix(item, "include:") || strings.HasPrefix(item, "redirect=") {
			parts := strings.Split(item, ":")
			if len(parts) < 2 {
				log.Printf("Formato inválido de mecanismo SPF: %s", item)
				continue
			}
			domain := parts[1]
			spfRecord, err := s.ObterSPFRecordParaDominio(domain)
			if err != nil {
				log.Printf("Erro ao obter registro SPF para domínio %s: %v", domain, err)
				continue
			}
			count++
			if spfRecord != "" {
				count += s.contarConsultasDNSRecursivo(spfRecord)
			}
		}
	}

	count += len(regexp.MustCompile(`\ba\b`).FindAllString(record, -1))
	count += len(regexp.MustCompile(`\bmx\b`).FindAllString(record, -1))
	count += len(regexp.MustCompile(`\bptr\b`).FindAllString(record, -1))
	count += len(regexp.MustCompile(`exists`).FindAllString(record, -1))

	return count
}

func (s *SPF) ObterSPFRecordParaDominio(dominio string) (string, error) {
	txtRecords, err := net.LookupTXT(dominio)
	if err != nil {
		return "", fmt.Errorf("erro ao consultar DNS para %s: %v", dominio, err)
	}
	if len(txtRecords) == 0 {
		return "", fmt.Errorf("nenhuma resposta DNS para %s", dominio)
	}
	for _, record := range txtRecords {
		if strings.Contains(record, "v=spf1") {
			return record, nil
		}
	}
	return "", fmt.Errorf("registro SPF não encontrado para %s", dominio)
}

func (s *SPF) String() string {
	return fmt.Sprintf("SPF Record: %s\nAll Mechanism: %s\nDNS Query Count: %d\nToo Many DNS Queries: %t\n",
		s.SPFRecord, s.AllMechanism, s.DNSQueryCount, s.TooManyDNSQueries)
}
