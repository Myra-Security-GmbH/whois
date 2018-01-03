package whois

import "net"

//
// IP ...
//
func IP(ip net.IP) (result QueryResult, err error) {
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
		return parseRipeFormat(data), nil

	case ApnicServer:
		return parseRipeFormat(data), nil

	case AfrinicServer:
		return parseRipeFormat(data), nil

	case LacnicServer:
		return parseRipeFormat(data), nil

	case ArinServer:
		return parseArinFormat(data), nil
	}

	return
}
