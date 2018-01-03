package whois

//
// parseRipeFormat parses whois output format of ripe.
//
func parseRipeFormat(in []byte) QueryResult {
	result := NewQueryResult(in)
	lastKey := ""
	lastToken := []byte{}
	currentToken := []byte{}
	valueMode := false

	currentRecord := make(map[string]string)

	for i := 0; i < len(in); i++ {
		tok := in[i]

		switch {
		case (tok == '%' && (i == 0 || (i > 0 && in[i-1] == '\n'))):
			for ; ; i++ {
				if in[i] == '\n' {
					break
				}
			}

			continue

		case (tok == '\n' && (i > 0 && in[i-1] == '\n')):
			// save old record and create a new one
			if len(currentRecord) > 0 {
				result.records = append(result.Records(), NewQueryRecord(currentRecord, 0))
				currentRecord = make(map[string]string)
			}
			continue

		case (tok == '\n' && len(in) > i+1 && in[i+1] == ' '):
			i++

			for ; in[i] == ' '; i++ {
				// loop until next character found
			}
			i -= 2 // want to keep a space
			continue

		case (tok == '\n' && len(in) > i+1 && in[i+1] != ' '):
			key := normalizeKey(string(lastToken))
			value := normalizeValue(string(currentToken))

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

		default:
			currentToken = append(currentToken, tok)
		}
	}

	if len(currentRecord) > 0 {
		result.records = append(result.Records(), NewQueryRecord(currentRecord, 0))
	}

	return result
}
