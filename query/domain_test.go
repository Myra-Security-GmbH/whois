// +building !testing

package query

import (
	"fmt"
	"net/url"
	"testing"
)

func TestDomain(t *testing.T) {

	url1 := "http://www.github.com"
	parsed, _ := url.Parse(url1)
	fmt.Println(parsed)
	for _, domain := range []string{parsed.Host} {
		Domain(domain)
	}
}
