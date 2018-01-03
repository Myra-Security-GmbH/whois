// !build +testing

package whois

import "testing"

func TestUrl(t *testing.T) {
	URL("https://www.github.com", nil)
}
