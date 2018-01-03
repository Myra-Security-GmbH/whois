# whois - a whois implementation/parser, written in go

[Documentation](https://godoc.org/github.com/Myra-Security-GmbH/whois)

### Examples
Query by Host:
```
exampleUrl := "https://github.com/Myra-Security-GmbH/whois"
parsedUrl, _ := url.Parse(exampleUrl)
parsedData, err := whois.Domain(domain)
if err != nil {
	fmt.Println(err)
	return
}
fmt.Println(parsedData[0]["city"])
//Output:
//San Francisco
```
Query by IP:
```
ip := net.ParseIP("194.25.2.129")
parsedData, err := whois.IP(ip)
if err != nil {
	fmt.Println(err)
	return
}
fmt.Println(parsedData[1]["org-name"])
// Output:
// Deutsche Telekom AG
```