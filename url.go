package whois

import pkgUrl "net/url"

//
// URL returns a whois from the domain name of an url.
//
func URL(url string, cache *KVCache) (result QueryResult, err error) {
	u, err := pkgUrl.Parse(url)

	if err != nil {
		return
	}

	return Domain(u.Host, cache)
}
