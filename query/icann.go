package query

import (
	"strings"
)

//
// parseICANNData parses whois output format of Internic.
//
func parseICANNData(in []byte) []map[string]string {
	ret := []map[string]string{}
	lastKey := ""
	lastToken := []byte{}
	currentToken := []byte{}
	valueMode := false

	currentRecord := make(map[string]string)

loop:
	for i := 0; i < len(in); i++ {
		tok := in[i]

		switch {
		case (tok == '\n'):
			key := strings.Trim(string(lastToken), " ")
			value := strings.Trim(string(currentToken), " ")

			if key != "" && value != "" {
				if lastKey == key {
					currentRecord[key] += "\n" + value
				} else {
					currentRecord[key] = value
				}

				lastKey = key
			}

			valueMode = false
			lastToken = []byte{}
			currentToken = []byte{}
			continue

		case (tok == ':' && !valueMode):
			valueMode = true
			lastToken = currentToken
			currentToken = []byte{}
			continue

		case (tok == '>' && len(in) > i+2 && in[i+1] == '>' && in[i+2] == '>'):
			break loop

		default:
			currentToken = append(currentToken, tok)
		}
	}

	if len(currentRecord) > 0 {
		ret = append(ret, currentRecord)
		currentRecord = make(map[string]string)
	}

	return ret
}
