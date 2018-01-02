// +build !testing

package whois

import (
	"testing"
)

func TestDomain(t *testing.T) {
	for _, domain := range []string{"google.net", "www.google.net"} {
		Domain(domain)
	}
}
