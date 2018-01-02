package query

import pkgUrl "net/url"

//
// Url returns a whois from the domain name of an url.
//
func Url(url string) ([]map[string]string, error) {
	u, err := pkgUrl.Parse(url)

	if err != nil {
		return nil, err
	}

	return Domain(u.Host)
}
