# Stop Email Spoofing!

![icon](https://github.com/user-attachments/assets/ed99d036-9c17-4ef2-9ea0-d8bc5c0d6e9d)

## What it is?
A command-line tool written in Go (Golang) - based on the project [Spoofy](https://github.com/MattKeeley/Spoofy) - for analyzing the vulnerability of domain names to email spoofing attacks and suggesting changes for mitigation.

## Features
[+] Attempts to locate DKIM (DomainKeys Identified Mail) record using the 100 most common selectors.

[+] Checks if there is a BIMI (Brand Indicators for Message Identification) record.

[+] Checks if the server uses a Catch-All configuration (for user enumeration prevention).

[+] Checks the existence and compliance of the SPF (Sender Policy Framework) record.

[+] Checks the existence and compliance of the DMARC (Domain-based Message Authentication, Reporting, and Conformance) record.

[+] Indicates whether the domain is vulnerable to email spoofing attacks and specifies the level of vulnerability*.

[+] Provides solutions to address and resolve the identified vulnerabilities*.

** The tool makes its conclusions according to what is found in [ULTIMATE_TABLE](https://github.com/v1sc0/stopemailspoofing/blob/main/ULTIMATE_TABLE.xlsx).

## Installation

## Usage

## Example
