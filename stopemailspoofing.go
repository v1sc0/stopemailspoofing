// stopemailspoofing.go
package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/v1sc0/stopemailspoofing/modules"

	"github.com/fatih/color"
)

type DomainResult struct {
	Domain            string `json:"domain"`
	DNSType           string `json:"dns_type"`
	SOARecord         string `json:"soa_record"`
	DNSServer         string `json:"dns_server"`
	MXRecords         string `json:"mx_records"`
	DKIMStatus        string `json:"dkim_status"`
	DKIMSelector      string `json:"dkim_selector"`
	DKIMRecord        string `json:"dkim_record"`
	BIMIStatus        string `json:"bimi_status"`
	BIMIRecord        string `json:"bimi_record"`
	CatchAll          string `json:"catch_all"`
	SPFStatus         string `json:"spf_status"`
	SPFRecord         string `json:"spf_record"`
	AllMechanism      string `json:"all_mechanism"`
	DNSQueryCount     int    `json:"dns_query_count"`
	TooManyDNSQueries bool   `json:"too_many_dns_queries"`
	DMARCStatus       string `json:"dmarc_status"`
	DMARCRecord       string `json:"dmarc_record"`
	Policy            string `json:"policy"`
	Pct               string `json:"pct"`
	ASPF              string `json:"aspf"`
	SubdomainPolicy   string `json:"subdomain_policy"`
	ForensicReports   string `json:"forensic_reports"`
	AggregateReports  string `json:"aggregate_reports"`
	Spoofing          string `json:"spoofing"`
}

func CapturarEntradaDominios() ([]string, error) {
	var dominios []string
	var escolha int

	fmt.Println("\nChoose an option:")
	fmt.Println("\n1. Enter single domain name manually")
	fmt.Println("2. Upload a list of domain names from a file")
	fmt.Print("\nEnter the number of the chosen option: ")
	fmt.Scan(&escolha)

	switch escolha {
	case 1:
		fmt.Print("\nType in the domain name (example.com): ")
		var dominio string
		fmt.Scan(&dominio)
		dominios = append(dominios, strings.TrimSpace(dominio))
	case 2:
		fmt.Print("\nType in the file path: ")
		var caminho string
		fmt.Scan(&caminho)
		loadedDomains, err := carregarDominiosDeArquivo(caminho)
		if err != nil {
			return nil, err
		}
		dominios = append(dominios, loadedDomains...)
	default:
		return nil, fmt.Errorf("Invalid option.")
	}
	return dominios, nil
}

func carregarDominiosDeArquivo(caminho string) ([]string, error) {
	var dominios []string
	file, err := os.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dominio := strings.TrimSpace(scanner.Text())
		if dominio != "" {
			dominios = append(dominios, dominio)
		}
	}
	return dominios, scanner.Err()
}

func SalvarResultadoEmCSV(result DomainResult, arquivo string) error {
	file, err := os.OpenFile(arquivo, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Error opening CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if stat, _ := file.Stat(); stat.Size() == 0 {
		writer.Write([]string{
			"Domain", "DNSType", "SOARecord", "DNSServer", "MXRecords",
			"DKIMStatus", "DKIMSelector", "DKIMRecord",
			"BIMIStatus", "BIMIRecord", "CatchAll", "SPFStatus", "SPFRecord",
			"AllMechanism", "DNSQueryCount", "TooManyDNSQueries",
			"DMARCStatus", "DMARCRecord", "Policy", "Pct", "ASPF",
			"SubdomainPolicy", "ForensicReports", "AggregateReports", "Spoofing",
		})
	}

	writer.Write([]string{
		result.Domain, result.DNSType, result.SOARecord, result.DNSServer, result.MXRecords,
		result.DKIMStatus, result.DKIMSelector, result.DKIMRecord,
		result.BIMIStatus, result.BIMIRecord, result.CatchAll, result.SPFStatus,
		result.SPFRecord, result.AllMechanism, fmt.Sprint(result.DNSQueryCount),
		fmt.Sprint(result.TooManyDNSQueries), result.DMARCStatus, result.DMARCRecord,
		result.Policy, result.Pct, result.ASPF, result.SubdomainPolicy,
		result.ForensicReports, result.AggregateReports, result.Spoofing,
	})

	return nil
}

func main() {

	catchAllVerifier := modules.NovoCatchAllVerifier()

	infoColor := color.New(color.FgWhite, color.Bold).SprintFunc()
	successColor := color.New(color.FgGreen, color.Bold).SprintFunc()
	errorColor := color.New(color.FgRed, color.Bold).SprintFunc()
	cyanTitleColor := color.New(color.FgCyan, color.Bold).SprintFunc()

	dominios, err := CapturarEntradaDominios()
	if err != nil {
		log.Fatal("Error when capturing domain name entries:", err)
	}

	for _, dominio := range dominios {
		fmt.Printf(cyanTitleColor("\n ===================== %s =====================\n"), dominio)

		dnsVerificacao := modules.NovoDNS(dominio)
		dnsResult := DomainResult{
			Domain:    dominio,
			DNSType:   dnsVerificacao.DomainType,
			SOARecord: dnsVerificacao.SOARecord,
			DNSServer: dnsVerificacao.DNSServer,
			MXRecords: strings.Join(dnsVerificacao.MXRecords, ", "),
		}
		fmt.Println(infoColor(dnsVerificacao))

		fmt.Println(cyanTitleColor("DKIM:"))
		dkimResultados := modules.VerificarDKIM([]string{dominio})
		dnsResult.DKIMStatus = "Not found"
		dnsResult.DKIMSelector = ""
		dnsResult.DKIMRecord = ""
		encontrouDKIM := false

		for _, resultado := range dkimResultados {
			if resultado.DKIMFound == "SIM" {
				fmt.Printf("%s Selector: %s, DKIM Record: %s\n", successColor("[+]"), resultado.Selector, resultado.DKIMRecord)
				dnsResult.DKIMStatus = "Found"
				dnsResult.DKIMSelector = resultado.Selector
				dnsResult.DKIMRecord = resultado.DKIMRecord
				encontrouDKIM = true
				break
			}
		}

		if !encontrouDKIM {
			fmt.Println(errorColor("[-] DKIM not found."))
		}

		fmt.Println(cyanTitleColor("\nBIMI:"))
		bimiVerificacao := modules.NovoBIMI(dominio, "8.8.8.8")
		if bimiVerificacao.BIMIRecord != "BIMI não encontrado" {
			fmt.Println(successColor("[+]"), bimiVerificacao)
			dnsResult.BIMIStatus = "Found"
			dnsResult.BIMIRecord = bimiVerificacao.BIMIRecord
		} else {
			fmt.Println(errorColor("[-] BIMI not found."))
			dnsResult.BIMIStatus = "Not found"
			dnsResult.BIMIRecord = ""
		}

		fmt.Println(cyanTitleColor("\nCatch-All:"))
		catchAllResult := catchAllVerifier.VerificarCatchAll(dominio)
		catchAllStatus := successColor("Yes")
		dnsResult.CatchAll = "Yes"
		if !catchAllResult.CatchAll {
			catchAllStatus = errorColor("No")
			dnsResult.CatchAll = "No"
		}
		fmt.Printf("%s Catch-All: %s, Error: %s\n", infoColor("[*]"), catchAllStatus, catchAllResult.Error)

		fmt.Println(cyanTitleColor("\nSPF:"))
		spfVerificacao := modules.NovoSPF(dominio)
		if spfVerificacao.SPFRecord != "" {
			fmt.Println(infoColor("[*]"), spfVerificacao)
			dnsResult.SPFStatus = "Found"
			dnsResult.SPFRecord = spfVerificacao.SPFRecord
			dnsResult.AllMechanism = spfVerificacao.AllMechanism
			dnsResult.DNSQueryCount = spfVerificacao.DNSQueryCount
			dnsResult.TooManyDNSQueries = spfVerificacao.DNSQueryCount > 10
		} else {
			fmt.Println(errorColor("[-] SPF not found.\n"))
			dnsResult.SPFStatus = "Not found"
			dnsResult.SPFRecord = ""
			dnsResult.AllMechanism = ""
			dnsResult.DNSQueryCount = 0
			dnsResult.TooManyDNSQueries = false
		}

		fmt.Println(cyanTitleColor("DMARC:"))
		dmarcVerificacao := modules.NovoDMARC(dominio, "8.8.8.8")
		if dmarcVerificacao.DMARCRecord != "" {
			fmt.Println(infoColor("[*]"), dmarcVerificacao)
			dnsResult.DMARCStatus = "Found"
			dnsResult.DMARCRecord = dmarcVerificacao.DMARCRecord
			dnsResult.Policy = dmarcVerificacao.Policy
			dnsResult.Pct = dmarcVerificacao.Pct
			dnsResult.ASPF = dmarcVerificacao.ASPF
			dnsResult.SubdomainPolicy = dmarcVerificacao.SubdomainPolicy
			dnsResult.ForensicReports = dmarcVerificacao.ForensicReports
			dnsResult.AggregateReports = dmarcVerificacao.AggregateReports
		} else {
			fmt.Println(errorColor("[-] DMARC not found.\n"))
			dnsResult.DMARCStatus = "Not found"
			dnsResult.DMARCRecord = ""
			dnsResult.Policy = ""
			dnsResult.Pct = ""
			dnsResult.ASPF = ""
			dnsResult.SubdomainPolicy = ""
			dnsResult.ForensicReports = ""
			dnsResult.AggregateReports = ""
		}

		fmt.Println(cyanTitleColor("Spoofing:"))
		spoofingVerificacao := modules.NovoSpoofing(
			dominio,
			spfVerificacao.AllMechanism,
			dmarcVerificacao.Policy,
			dmarcVerificacao.ASPF,
			dmarcVerificacao.SubdomainPolicy,
			dmarcVerificacao.DMARCRecord,
		)
		spoofingColor := errorColor
		if spoofingVerificacao.Spoofability == "Not spoofable." {
			spoofingColor = successColor
		}
		spoofableMessage := fmt.Sprintf("%s %s", infoColor("[*] Spoofability:"), spoofingColor(spoofingVerificacao.Spoofability))
		fmt.Println(spoofableMessage)
		dnsResult.Spoofing = spoofingVerificacao.Spoofability

		fmt.Println(cyanTitleColor("\nFor additional security it is recommended:"))
		suggestions := modules.Suggestion(
			spfVerificacao.AllMechanism,
			dmarcVerificacao.Policy,
			dmarcVerificacao.ASPF,
			dmarcVerificacao.SubdomainPolicy,
		)
		fmt.Println(successColor(suggestions))

		if dmarcVerificacao.Pct == "" {
			fmt.Println(successColor("DMARC PCT: Consider adding pct=100."))
		}
		if dmarcVerificacao.ForensicReports == "" {
			fmt.Println(successColor("DMARC RUF: Consider adding an email address like ruf=example@example.mail"))
		}
		if dmarcVerificacao.AggregateReports == "" {
			fmt.Println(successColor("DMARC RUA: Consider adding an email address like ruf=example@example.mail"))
		}
		if dnsResult.DKIMStatus == "Not found" {
			fmt.Println(successColor("DKIM: Make sure to have DKIM record set up."))
		}
		if dnsResult.BIMIStatus == "Not found" {
			fmt.Println(successColor("BIMI: Consider setting up a BIMI record."))
		}
		if dnsResult.CatchAll == "No" {
			fmt.Println(successColor("CatchAll: Consider enabling CatchAll."))
		}

		if err := SalvarResultadoEmCSV(dnsResult, "results.csv"); err != nil {
			log.Printf("Error when saving in CSV for the domain %s: %v\n", dominio, err)
		}
	}

	fmt.Println("\nResults saved in results.csv\n")
}
