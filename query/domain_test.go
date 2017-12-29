// +building !testing

package query

import "testing"

func TestDomain(t *testing.T) {
	for _, domain := range []string{"myracloud.com"} {
		Domain(domain)
	}
}
