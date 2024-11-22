# Stop Email Spoofing!

![icon](https://github.com/user-attachments/assets/ed99d036-9c17-4ef2-9ea0-d8bc5c0d6e9d)

## What it is?
A command-line tool written in Go (Golang) - inspired on the project [Spoofy](https://github.com/MattKeeley/Spoofy) - for analyzing the vulnerability of domain names to email spoofing attacks and suggesting changes for mitigation.

## How it works?
[+] Accepts either a single domain name or a path to a list of domain names.

[+] Checks if the entry corresponds to a organizational domain or a subdomain.

[+] Gets SOA, NS and MX records.

[+] Attempts to locate DKIM (DomainKeys Identified Mail) record using the 100 most common selectors.

[+] Checks if there is a BIMI (Brand Indicators for Message Identification) record.

[+] Checks if the server uses a Catch-All configuration (for user enumeration prevention).

[+] Checks the existence and compliance of the SPF (Sender Policy Framework) record.

[+] Checks the existence and compliance of the DMARC (Domain-based Message Authentication, Reporting, and Conformance) record.

[+] Indicates whether the domain is vulnerable to email spoofing attacks and specifies the level of vulnerability*.

[+] Provides solutions to address and resolve the identified vulnerabilities*.

[+] Generates a CSV file with the results.

** The tool makes its conclusions according to what is found in [ULTIMATE_TABLE](https://github.com/v1sc0/stopemailspoofing/blob/main/ULTIMATE_TABLE.xlsx).

## Installation

1. Install Golang https://go.dev/doc/install (v1.23.1 at least)
   
2. ```
   git clone https://github.com/v1sc0/stopemailspoofing.git
   cd stopemailspoofing/
   go build

## Usage

```
./stopemailspoofing
```

![image](https://github.com/user-attachments/assets/c8d67219-f340-4633-ad53-bfa173c92761)

## Output example

![image](https://github.com/user-attachments/assets/d6d48ec1-c92c-415c-a811-693ce91b1edc)

