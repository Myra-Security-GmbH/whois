package whois

import (
	"strings"
)

//
// Domain performs a whois query for the given domain or hostname.
//
func Domain(domainOrHost string, cache *KVCache) (result QueryResult, err error) {
	domain, tld := domainTld(domainOrHost)

	if cache != nil {
		var found bool
		result, found = cache.Get(domain)
		if found {
			return
		}
	}

	whoisServer := IanaServer
	result, _, err = findWhois(whoisServer, tld, domain)

	if cache != nil {
		cache.Add(domain, result)
	}

	return
}

//
// domainTld returns the domain and tld from the given domain.
// it removes all hosts related parts from the fqdn.
//
func domainTld(domain string) (string, string) {
	domainParts := strings.Split(domain, ".")

	for i := 1; i < len(domainParts)-2; i++ {
		eTld := strings.Join(domainParts[i:], ".")

		tld, ok := tldlist[eTld]

		if ok && tld {
			return strings.Join(domainParts[i-1:], "."), eTld
		}
	}

	// in theory this should no happen but use the simple
	// way to have at least a fallback
	return strings.Join(domainParts[len(domainParts)-2:], "."), domainParts[len(domainParts)-1]
}

//
// findWhois loops ofer whois servers and tries to find the server responsible for the the domain.
//
// -> start @whois.iana.org via tld
// -> fetch data from whois tld server
// -> loop as long a registrant whois server is set in the records
//
func findWhois(server string, queryData string, domain string) (parsedData QueryResult, whoisServer string, err error) {
	data, err := query(server, queryData)
	if err != nil {
		return
	}

	var format string
	switch server {
	case DenicServer:
		format = FormatDenic
	case IanaServer:
		format = FormatIana
	default:
		format = FormatIcaan
	}

	parsedData = Parse(data, format)
	parsedData.target = domain

	whoisServer = server
	for _, d := range parsedData.Records() {
		for _, key := range []string{"whois", "Registrar WHOIS Server"} {
			whois, ok := d.data[key]

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
