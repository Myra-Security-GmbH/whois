package query

import "net"

const (
	// RipeServer used for ip/net queries
	RipeServer = "whois.ripe.net:43"

	// ApnicServer ...
	ApnicServer = "whois.apnic.net:43"

	// ArinServer ...
	ArinServer = "whois.arin.net:43"

	// AfrinicServer ...
	AfrinicServer = "whois.afrinic.net:43"

	// LacnicServer ...
	LacnicServer = "whois.lacnic.net:43"

	// IanaServer ...
	IanaServer = "whois.iana.org:43"
)

// networkAssignment ...
type networkAssignment struct {
	net    net.IPNet
	server string
}

var networkList = make(map[int][]*networkAssignment)

// newAssignment ...
func newAssignment(cidr string, server string) *networkAssignment {
	ret := &networkAssignment{
		server: server,
	}

	_, n, _ := net.ParseCIDR(cidr)

	ret.net = *n

	return ret
}

func init() {
	networkList[6] = []*networkAssignment{
		newAssignment("2001:0000::/23", IanaServer),
		newAssignment("2001:0200::/23", ApnicServer),
		newAssignment("2001:0400::/23", ArinServer),
		//newAssignment("2001:0600::/23", RipeServer),
		//newAssignment("2001:0800::/23", RipeServer),
		//newAssignment("2001:0a00::/23", RipeServer),
		newAssignment("2001:0c00::/23", ApnicServer),
		newAssignment("2001:0e00::/23", ApnicServer),
		newAssignment("2001:1200::/23", LacnicServer),
		//newAssignment("2001:1400::/23", RipeServer),
		//newAssignment("2001:1600::/23", RipeServer),
		newAssignment("2001:1800::/23", ArinServer),
		//newAssignment("2001:1a00::/23", RipeServer),
		//newAssignment("2001:1c00::/22", RipeServer),
		//newAssignment("2001:2000::/20", RipeServer),
		//newAssignment("2001:3000::/21", RipeServer),
		//newAssignment("2001:3800::/22", RipeServer),
		//newAssignment("2001:4000::/23", RipeServer),
		newAssignment("2001:4200::/23", AfrinicServer),
		newAssignment("2001:4400::/23", ApnicServer),
		//newAssignment("2001:4600::/23", RipeServer),
		newAssignment("2001:4800::/23", ArinServer),
		//newAssignment("2001:4a00::/23", RipeServer),
		//newAssignment("2001:4c00::/23", RipeServer),
		//newAssignment("2001:5000::/20", RipeServer),
		newAssignment("2001:8000::/19", ApnicServer),
		newAssignment("2001:a000::/20", ApnicServer),
		newAssignment("2001:b000::/20", ApnicServer),
		//newAssignment("2003:0000::/18", RipeServer),
		newAssignment("2400:0000::/12", ApnicServer),
		newAssignment("2600:0000::/12", ArinServer),
		newAssignment("2610:0000::/23", ArinServer),
		newAssignment("2620:0000::/23", ArinServer),
		newAssignment("2800:0000::/12", LacnicServer),
		//newAssignment("2a00:0000::/12", RipeServer),
		newAssignment("2c00:0000::/12", AfrinicServer),
	}

	networkList[4] = []*networkAssignment{
		newAssignment("1.0.0.0/8", ApnicServer),
		//newAssignment("2.0.0.0/8", RipeServer),
		//newAssignment("5.0.0.0/8", RipeServer),
		newAssignment("8.0.0.0/8", ApnicServer),
		newAssignment("14.0.0.0/8", ApnicServer),
		newAssignment("23.0.0.0/8", ArinServer),
		newAssignment("24.0.0.0/8", ArinServer),
		newAssignment("27.0.0.0/8", ApnicServer),
		//newAssignment("31.0.0.0/8", RipeServer),
		newAssignment("36.0.0.0/8", ApnicServer),
		//newAssignment("37.0.0.0/8", RipeServer),
		newAssignment("39.0.0.0/8", ApnicServer),
		newAssignment("41.0.0.0/8", AfrinicServer),
		newAssignment("42.0.0.0/8", ApnicServer),
		//newAssignment("46.0.0.0/8", RipeServer),
		newAssignment("49.0.0.0/8", ApnicServer),
		newAssignment("50.0.0.0/8", ArinServer),
		newAssignment("58.0.0.0/8", ApnicServer),
		newAssignment("59.0.0.0/8", ApnicServer),
		newAssignment("60.0.0.0/8", ApnicServer),
		newAssignment("61.0.0.0/8", ApnicServer),
		//newAssignment("62.0.0.0/8", RipeServer),
		newAssignment("63.0.0.0/8", ArinServer),
		newAssignment("64.0.0.0/8", ArinServer),
		newAssignment("65.0.0.0/8", ArinServer),
		newAssignment("66.0.0.0/8", ArinServer),
		newAssignment("67.0.0.0/8", ArinServer),
		newAssignment("68.0.0.0/8", ArinServer),
		newAssignment("69.0.0.0/8", ArinServer),
		newAssignment("70.0.0.0/8", ArinServer),
		newAssignment("71.0.0.0/8", ArinServer),
		newAssignment("72.0.0.0/8", ArinServer),
		newAssignment("73.0.0.0/8", ArinServer),
		newAssignment("74.0.0.0/8", ArinServer),
		newAssignment("75.0.0.0/8", ArinServer),
		newAssignment("76.0.0.0/8", ArinServer),
		//newAssignment("77.0.0.0/8", RipeServer),
		//newAssignment("78.0.0.0/8", RipeServer),
		//newAssignment("79.0.0.0/8", RipeServer),
		//newAssignment("80.0.0.0/8", RipeServer),
		//newAssignment("81.0.0.0/8", RipeServer),
		//newAssignment("82.0.0.0/8", RipeServer),
		//newAssignment("83.0.0.0/8", RipeServer),
		//newAssignment("84.0.0.0/8", RipeServer),
		//newAssignment("85.0.0.0/8", RipeServer),
		//newAssignment("86.0.0.0/8", RipeServer),
		//newAssignment("87.0.0.0/8", RipeServer),
		//newAssignment("88.0.0.0/8", RipeServer),
		//newAssignment("89.0.0.0/8", RipeServer),
		//newAssignment("90.0.0.0/8", RipeServer),
		//newAssignment("91.0.0.0/8", RipeServer),
		//newAssignment("92.0.0.0/8", RipeServer),
		//newAssignment("93.0.0.0/8", RipeServer),
		//newAssignment("94.0.0.0/8", RipeServer),
		//newAssignment("95.0.0.0/8", RipeServer),
		newAssignment("96.0.0.0/8", ArinServer),
		newAssignment("97.0.0.0/8", ArinServer),
		newAssignment("98.0.0.0/8", ArinServer),
		newAssignment("99.0.0.0/8", ArinServer),
		newAssignment("100.0.0.0/8", ArinServer),
		newAssignment("101.0.0.0/8", ApnicServer),
		newAssignment("102.0.0.0/8", AfrinicServer),
		newAssignment("103.0.0.0/8", ApnicServer),
		newAssignment("104.0.0.0/8", ArinServer),
		newAssignment("105.0.0.0/8", AfrinicServer),
		newAssignment("106.0.0.0/8", ApnicServer),
		newAssignment("107.0.0.0/8", ArinServer),
		newAssignment("108.0.0.0/8", ArinServer),
		//newAssignment("109.0.0.0/8", RipeServer),
		newAssignment("110.0.0.0/8", ApnicServer),
		newAssignment("111.0.0.0/8", ApnicServer),
		newAssignment("112.0.0.0/8", ApnicServer),
		newAssignment("113.0.0.0/8", ApnicServer),
		newAssignment("114.0.0.0/8", ApnicServer),
		newAssignment("115.0.0.0/8", ApnicServer),
		newAssignment("116.0.0.0/8", ApnicServer),
		newAssignment("117.0.0.0/8", ApnicServer),
		newAssignment("118.0.0.0/8", ApnicServer),
		newAssignment("119.0.0.0/8", ApnicServer),
		newAssignment("120.0.0.0/8", ApnicServer),
		newAssignment("121.0.0.0/8", ApnicServer),
		newAssignment("122.0.0.0/8", ApnicServer),
		newAssignment("123.0.0.0/8", ApnicServer),
		newAssignment("124.0.0.0/8", ApnicServer),
		newAssignment("125.0.0.0/8", ApnicServer),
		newAssignment("126.0.0.0/8", ApnicServer),
		newAssignment("173.0.0.0/8", ArinServer),
		newAssignment("174.0.0.0/8", ArinServer),
		newAssignment("175.0.0.0/8", ApnicServer),
		//newAssignment("176.0.0.0/8", RipeServer),
		newAssignment("177.0.0.0/8", LacnicServer),
		//newAssignment("178.0.0.0/8", RipeServer),
		newAssignment("179.0.0.0/8", LacnicServer),
		newAssignment("180.0.0.0/8", ApnicServer),
		newAssignment("181.0.0.0/8", LacnicServer),
		newAssignment("182.0.0.0/8", ApnicServer),
		newAssignment("183.0.0.0/8", ApnicServer),
		newAssignment("184.0.0.0/8", ArinServer),
		//newAssignment("185.0.0.0/8", RipeServer),
		newAssignment("186.0.0.0/8", LacnicServer),
		newAssignment("187.0.0.0/8", LacnicServer),
		newAssignment("189.0.0.0/8", LacnicServer),
		newAssignment("190.0.0.0/8", LacnicServer),
		//newAssignment("193.0.0.0/8", RipeServer),
		//newAssignment("194.0.0.0/8", RipeServer),
		//newAssignment("195.0.0.0/8", RipeServer),
		newAssignment("197.0.0.0/8", AfrinicServer),
		newAssignment("199.0.0.0/8", ArinServer),
		newAssignment("200.0.0.0/8", LacnicServer),
		newAssignment("201.0.0.0/8", LacnicServer),
		newAssignment("202.0.0.0/8", ApnicServer),
		newAssignment("203.0.0.0/8", ApnicServer),
		newAssignment("204.0.0.0/8", ArinServer),
		newAssignment("205.0.0.0/8", ArinServer),
		newAssignment("206.0.0.0/8", ArinServer),
		newAssignment("207.0.0.0/8", ArinServer),
		newAssignment("208.0.0.0/8", ArinServer),
		newAssignment("209.0.0.0/8", ArinServer),
		newAssignment("210.0.0.0/8", ApnicServer),
		newAssignment("211.0.0.0/8", ApnicServer),
		//newAssignment("212.0.0.0/8", RipeServer),
		//newAssignment("213.0.0.0/8", RipeServer),
		newAssignment("216.0.0.0/8", ArinServer),
		//newAssignment("217.0.0.0/8", RipeServer),
		newAssignment("218.0.0.0/8", ApnicServer),
		newAssignment("219.0.0.0/8", ApnicServer),
		newAssignment("220.0.0.0/8", ApnicServer),
		newAssignment("221.0.0.0/8", ApnicServer),
		newAssignment("222.0.0.0/8", ApnicServer),
		newAssignment("223.0.0.0/8", ApnicServer),
	}
}

//
// DetermineWhoisServerForIP returns the whois server
// responsible for the given ip network.
//
func DetermineWhoisServerForIP(ip net.IP) string {
	ipVersion := 4

	if ip.To4() == nil {
		ipVersion = 6
	}

	for _, as := range networkList[ipVersion] {
		if as.net.Contains(ip) {
			return as.server
		}
	}

	return RipeServer
}
