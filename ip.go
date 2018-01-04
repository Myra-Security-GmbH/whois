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

	switch server {
	case RipeServer:
		result = parseRipeFormat(data)

	case ApnicServer:
		result = parseRipeFormat(data)

	case AfrinicServer:
		result = parseRipeFormat(data)

	case LacnicServer:
		result = parseRipeFormat(data)

	case ArinServer:
		result = parseArinFormat(data)
	}
	result.target = ip.String()

	if cache != nil {
		cache.Add(ip.String(), result)
	}

	return
}
