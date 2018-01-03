package whois

import (
	"strings"

	"github.com/fatih/camelcase"
)

//
// normalizeKey normalizes the given keys from the whois formats
//
func normalizeKey(key string) string {
	ret := strings.Trim(key, " -\r")
next:
	switch {
	case (strings.Index(ret, "Tech ") == 0):
		ret = ret[5:]
		goto next

	case (strings.Index(ret, "Admin ") == 0):
		ret = ret[6:]
		goto next

	case (strings.Index(ret, "Registrant ") == 0):
		ret = ret[11:]
		goto next

	case (strings.Index(ret, "Registrar ") == 0):
		ret = ret[10:]
		goto next

	case (strings.Index(ret, "OrgTech") == 0):
		ret = ret[7:]
		goto next

	case (strings.Index(ret, "OrgAdmin") == 0), (strings.Index(ret, "OrgAbuse") == 0):
		ret = ret[8:]
		goto next

	case (strings.Index(ret, "Net") == 0):
		ret = ret[3:]
		goto next

	case (ret == "StateProv"):
		ret = "StateProvince"

	case (ret == "fax-no"):
		ret = "fax"

	case (ret == "e-mail"):
		ret = "email"

	case (ret == "OrgName"):
		ret = "organization"

	case (ret == "OrgId"):
		ret = "id"

	case (ret == "WHOIS Server"):
		ret = "whois"

	case (ret == "inetnum"):
		ret = "range"

	case (strings.Index(ret, "-") > 0):
		return strings.ToLower(ret)
	}

	ret = strings.Replace(ret, " ", "", -1)
	ret = strings.Replace(ret, "/", "-", -1)

	split := camelcase.Split(ret)
	ret = strings.ToLower(strings.Join(split, "-"))

	return ret
}

//
// normalizeValue normalizes the given value and removes
// useless parts like control characters and trailing / beginning spaces.
//
func normalizeValue(value string) string {
	value = strings.Trim(value, " \r")
	ret := make([]byte, len(value))
	pos := 0

	//
	// pretty slow ..
	// TODO: find a faster solution
	//
	for i := 0; i < len(value); i++ {
		if value[i] != '\n' && byte(value[i]) < 30 {
			continue
		}

		ret[pos] = value[i]

		pos++
	}

	return string(ret[:pos])
}
