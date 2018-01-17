package whois

import (
	"fmt"
	"io"
	"net"
)

const (
	// FormatDenic ...
	FormatDenic = "denic"
	// FormatIana ...
	FormatIana = "iana"
	// FormatRipe ...
	FormatRipe = "ripe"
	// FormatApnic ...
	FormatApnic = "apnic"
	// FormatAfrinic ...
	FormatAfrinic = "afrinic"
	// FormatLacnic ...
	FormatLacnic = "lacnic"
	// FormatArin ...
	FormatArin = "arin"
	// FormatIcaan ...
	FormatIcaan = "icaan"
)

//
// query the given server, passing the given data
//
func query(server string, data string) ([]byte, error) {
	conn, err := net.Dial("tcp", server)

	if err != nil {
		return nil, err
	}

	switch server {
	case ArinServer:
		data = "n + " + data
	case DenicServer:
		data = "-T dn,ace " + data
	}

	n, err := conn.Write([]byte(data + "\r\n"))

	if err != nil {
		return nil, err
	}

	if n != len(data)+2 {
		return nil, fmt.Errorf("expected %d bytes sent, %d were sent", len(data)+2, n)
	}

	ret := []byte{}
	tmp := make([]byte, 65536)

	for {
		n, err = conn.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		ret = append(ret, tmp[0:n]...)
	}

	return ret, nil
}

//
// Parse the given raw data using a format specific parse function
//
func Parse(raw []byte, format string) (parsed QueryResult) {
	switch format {
	case FormatDenic:
		parsed = parseDenicFormat(raw)
	case FormatIana:
		parsed = parseRipeFormat(raw)
	case FormatRipe:
		parsed = parseRipeFormat(raw)
	case FormatApnic:
		parsed = parseRipeFormat(raw)
	case FormatAfrinic:
		parsed = parseRipeFormat(raw)
	case FormatLacnic:
		parsed = parseRipeFormat(raw)
	case FormatArin:
		parsed = parseArinFormat(raw)
	case FormatIcaan:
		parsed = parseICANNData(raw)
	default:
		parsed = parseICANNData(raw)
	}

	return
}
