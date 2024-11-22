// modules/catchall.go
package modules

import (
	"fmt"

	emailverifier "github.com/AfterShip/email-verifier"
)

type CatchAllResult struct {
	Domain   string
	HasMX    bool
	CatchAll bool
	Error    string
}

type CatchAllVerifier struct {
	verifier *emailverifier.Verifier
}

func NovoCatchAllVerifier() *CatchAllVerifier {
	verifier := emailverifier.NewVerifier().EnableSMTPCheck()
	return &CatchAllVerifier{verifier: verifier}
}

func (c *CatchAllVerifier) VerificarCatchAll(domain string) CatchAllResult {
	var result CatchAllResult
	result.Domain = domain

	mxResult, err := c.verifier.CheckMX(domain)
	if err != nil {
		result.Error = fmt.Sprintf("Erro MX: %v", err)
		result.HasMX = false
	} else {
		result.HasMX = mxResult.HasMXRecord
	}

	if result.HasMX {
		smtpResult, err := c.verifier.CheckSMTP(domain, "")
		if err != nil {
			result.Error += fmt.Sprintf(" Erro SMTP: %v", err)
			result.CatchAll = false
		} else {
			result.CatchAll = smtpResult.CatchAll
		}
	} else {
		result.CatchAll = false
	}

	return result
}
