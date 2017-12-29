package query

import (
	"fmt"
	"strings"
)

//
// Domain performs a whois query for the given domain.
//
func Domain(domain string) {
	var parsedData []map[string]string

	domainParts := strings.Split(domain, ".")

	// simple tld detection
	// ignore de.vu etc domains
	tld := domainParts[len(domainParts)-1]

	whoisServer, ok := domainList[tld]

	if !ok {
		// fallback
		whoisServer = tld + ".whois-server.net"
	}

	data, err := query(whoisServer, domain)

	if err != nil {
		fmt.Println(err)
		return
	}

	switch whoisServer {
	case "whois.denic.de:43":
		parsedData = parseDenicFormat(data)

	default:
		parsedData = parseICANNData(data)
	}

	fmt.Printf("%+v\n\n", parsedData)
}
