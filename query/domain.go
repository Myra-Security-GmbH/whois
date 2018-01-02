package query

import (
	"fmt"
	"strings"
)

//
// Domain performs a whois query for the given domain.
//
func Domain(domain string) {
	//var parsedData []map[string]string

	domainParts := strings.Split(domain, ".")

	// simple tld detection
	// ignore de.vu etc domains
	tld := domainParts[len(domainParts)-1]

	whoisServer := "whois.iana.org:43"
	parsedData, _, err := findWhois(whoisServer, tld, domain)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%+v\n\n", parsedData)
}

func findWhois(server string, queryData string, domain string) (parsedData []map[string]string, whoisServer string, err error) {
	data, err := query(server, queryData)
	if err != nil {
		return
	}

	switch server {
	case "whois.denic.de:43":
		parsedData = parseDenicFormat(data)
	case "whois.iana.org:43":
		parsedData = parseRipeFormat(data)
	default:
		parsedData = parseICANNData(data)
	}

	whoisServer = server
	for _, d := range parsedData {
		for _, key := range []string{"whois", "Registrar WHOIS Server"} {
			whois, ok := d[key]

			if ok && len(whois) > 0 {
				whoisServer := whois + ":43"
				if whoisServer != server {
					return findWhois(whoisServer, domain, domain)
				}
			}
		}
	}
	return
}
