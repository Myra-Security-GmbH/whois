package whois

import (
	"net"
)

//
// IP performs a whois query for the given net.IP.
//
func IP(ip net.IP, cache *KVCache) (result QueryResult, err error) {

	if cache != nil {
		var found bool
		result, found = cache.Get(ip.String())
		if found {
			return
		}
	}

	server := DetermineWhoisServerForIP(ip)

	data, err := query(
		server,
		ip.String(),
	)
	if err != nil {
		return
	}

	var format string
	switch server {
	case RipeServer:
		format = FormatRipe
	case ApnicServer:
		format = FormatApnic
	case AfrinicServer:
		format = FormatAfrinic
	case LacnicServer:
		format = FormatLacnic
	case ArinServer:
		format = FormatArin
	default:
		format = FormatRipe
	}

	result = Parse(data, format)
	result.target = ip.String()

	if cache != nil {
		cache.Add(ip.String(), result)
	}

	return
}
