package query

import "net"

//
// IP ...
//
func IP(ip net.IP) ([]map[string]string, error) {
	server := DetermineWhoisServerForIP(ip)

	data, err := query(
		server,
		ip.String(),
	)

	if err != nil {
		return nil, err
	}

	switch server {
	case RipeServer:
		return parseRipeFormat(data), nil

	case ApnicServer:
		return parseRipeFormat(data), nil

	case ArinServer:
		return parseArinFormat(data), nil
	}

	return nil, nil
}
