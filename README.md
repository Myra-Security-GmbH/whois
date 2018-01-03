# whois - a whois implementation/parser, written in go

[Documentation](https://godoc.org/github.com/Myra-Security-GmbH/whois)

### Examples
Query by URL:
```
parsedData, err := whois.Domain("https://github.com/Myra-Security-GmbH/whois")
if err != nil {
	fmt.Println(err)
	return
}
fmt.Println(parsedData[0]["city"])
//Output:
//San Francisco
```
Query by Host/Domain:
```
parsedData, err := whois.Domain("google.net")
if err != nil {
	fmt.Println(err)
	return
}
fmt.Println(parsedData[0]["city"])
//Output:
//Mountain View
```
Query by IP:
```
parsedData, err := whois.IP(net.ParseIP("194.25.2.129"))
if err != nil {
	fmt.Println(err)
	return
}
fmt.Println(parsedData[1]["org-name"])
// Output:
// Deutsche Telekom AG
```