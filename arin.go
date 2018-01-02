package whois

//
// parseArinFormat parses whois output format of Arin.
//
func parseArinFormat(in []byte) []map[string]string {
	ret := []map[string]string{}
	lastKey := ""
	lastToken := []byte{}
	currentToken := []byte{}
	valueMode := false

	currentRecord := make(map[string]string)

	for i := 0; i < len(in); i++ {
		tok := in[i]

		switch {
		case (tok == '#' && (i == 0 || (i > 0 && in[i-1] == '\n'))):
			for ; ; i++ {
				if in[i] == '\n' {
					break
				}
			}

			continue

		case (tok == '\n' && (i > 0 && in[i-1] == '\n')):
			// save old record and create a new one
			if len(currentRecord) > 0 {
				ret = append(ret, currentRecord)
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
		ret = append(ret, currentRecord)
		currentRecord = make(map[string]string)
	}

	return ret
}
