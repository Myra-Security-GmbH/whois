package query

import (
	"fmt"
	"io"
	"net"
)

func query(server string, data string) ([]byte, error) {
	conn, err := net.Dial("tcp", server)

	if err != nil {
		return nil, err
	}

	switch server {
	case ArinServer:
		data = "n + " + data
	case "whois.denic.de:43":
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
