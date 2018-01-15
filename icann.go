package whois

import (
	"strings"
)

//
// parseICANNData parses whois output format of Internic.
//
func parseICANNData(in []byte) QueryResult {
	result := NewQueryResult(in)
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
			key := normalizeKey(string(lastToken))
			value := normalizeValue(string(currentToken))

			if strings.Index(key, "Registry ") == 0 && len(currentRecord) > 0 && len(value) == 0 {
				zoneType := RecordTypeOther

				switch key[9:] {
				case "Domain ID":
					zoneType = RecordTypeDomain

				case "Registrant ID":
					zoneType = RecordTypeOwner

				case "Admin ID":
					zoneType = RecordTypeAdminC

				case "Tech ID":
					zoneType = RecordTypeTechC
				}

				result.records = append(result.Records(), NewQueryRecord(currentRecord, zoneType))
				currentRecord = make(map[string]string)
			}

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
		result.records = append(result.Records(), NewQueryRecord(currentRecord, 0))
	}

	return result
}
