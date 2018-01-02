package whois

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIP1(t *testing.T) {
	data, err := IP(net.ParseIP("194.25.2.129"))

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 5, len(data))

	// record 1
	require.Equal(t, "194.25.2.0 - 194.25.3.255", data[0]["range"])
	require.Equal(t, "DTAG-ONLINE1", data[0]["netname"])
	require.Equal(t, "Deutsche Telekom AG", data[0]["descr"])
	require.Equal(t, "ORG-DTAG1-RIPE", data[0]["org"])
	require.Equal(t, "DE", data[0]["country"])
	require.Equal(t, "DTIP", data[0]["admin-c"])
	require.Equal(t, "DTST", data[0]["tech-c"])
	require.Equal(t, "ASSIGNED PA", data[0]["status"])
	require.Equal(t, "DTAG-NIC", data[0]["mnt-by"])
	require.Equal(t, "2002-01-08T09:31:19Z", data[0]["created"])
	require.Equal(t, "2014-06-18T09:38:18Z", data[0]["last-modified"])
	require.Equal(t, "RIPE", data[0]["source"])

	// record 2
	require.Equal(t, "ORG-DTAG1-RIPE", data[1]["organisation"])
	require.Equal(t, "Deutsche Telekom AG", data[1]["org-name"])
	require.Equal(t, "OTHER", data[1]["org-type"])
	require.Equal(t, "Group Information Security, SDA/Abuse\nT-Online-Allee 1\nDE 64295 Darmstadt", data[1]["address"])
	require.Equal(t, "abuse contact in case of Spam, hack attacks, illegal activity, violation, scans, probes, etc.", data[1]["remarks"])
	require.Equal(t, "DTAG-NIC", data[1]["mnt-ref"])
	require.Equal(t, "DTAG-NIC", data[1]["mnt-by"])
	require.Equal(t, "DTAG4-RIPE", data[1]["abuse-c"])
	require.Equal(t, "2014-06-17T11:47:04Z", data[1]["created"])
	require.Equal(t, "2014-06-17T11:47:04Z", data[1]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[1]["source"])

	// record 3
	require.Equal(t, "DTAG Global IP-Addressing", data[2]["person"])
	require.Equal(t, "Deutsche Telekom AG\nDarmstadt, Germany", data[2]["address"])
	require.Equal(t, "+49 180 2 33 1000", data[2]["phone"])
	require.Equal(t, "+49 6151 6809399", data[2]["fax"])
	require.Equal(t, "DTIP", data[2]["nic-hdl"])
	require.Equal(t, "DTAG-NIC", data[2]["mnt-by"])
	require.Equal(t, "2003-01-29T10:22:59Z", data[2]["created"])
	require.Equal(t, "2015-11-27T08:02:45Z", data[2]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[2]["source"])

	// record 4
	require.Equal(t, "Security Team", data[3]["person"])
	require.Equal(t, "Deutsche Telekom AG\nDarmstadt, Germany", data[3]["address"])
	require.Equal(t, "+49 180 2 33 1000", data[3]["phone"])
	require.Equal(t, "+49 6151 6809399", data[3]["fax"])
	require.Equal(t, "DTST", data[3]["nic-hdl"])
	require.Equal(t, "DTAG-NIC", data[3]["mnt-by"])
	require.Equal(t, "2003-01-29T10:31:11Z", data[3]["created"])
	require.Equal(t, "2015-11-27T08:03:38Z", data[3]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[3]["source"])

	// record 5
	require.Equal(t, "194.25.0.0/16", data[4]["route"])
	require.Equal(t, "Deutsche Telekom AG, Internet service provider", data[4]["descr"])
	require.Equal(t, "AS3320", data[4]["origin"])
	require.Equal(t, "AS3320:RS-PA-TELEKOM", data[4]["member-of"])
	require.Equal(t, "DTAG-RR", data[4]["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data[4]["created"])
	require.Equal(t, "2004-06-15T17:32:45Z", data[4]["last-modified"])
	require.Equal(t, "RIPE", data[4]["source"])

}

func TestIP2(t *testing.T) {
	data, err := IP(net.ParseIP("212.18.0.5"))

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 4, len(data))

	require.Equal(t, "212.18.0.0 - 212.18.0.255", data[0]["range"])
	require.Equal(t, "MNET", data[0]["netname"])
	require.Equal(t, "M-net Telekommunikations GmbH", data[0]["descr"])
	require.Equal(t, "DE", data[0]["country"])
	require.Equal(t, "JV266-RIPE", data[0]["admin-c"])
	require.Equal(t, "MNET1-RIPE", data[0]["tech-c"])
	require.Equal(t, "ASSIGNED PA", data[0]["status"])
	require.Equal(t, "MNET-MNT", data[0]["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data[0]["created"])
	require.Equal(t, "2006-07-28T12:57:53Z", data[0]["last-modified"])
	require.Equal(t, "RIPE", data[0]["source"])

	require.Equal(t, "Hostmaster Role-Account", data[1]["role"])
	require.Equal(t, "M-net Telekommunikations GmbH\nEmmy-Noether-Str. 2\nD-80992 Muenchen\nGermany", data[1]["address"])
	require.Equal(t, "+49 89 45200 5907", data[1]["phone"])
	require.Equal(t, "+49 89 45200 3984", data[1]["fax"])
	require.Equal(t, "abuse@m-online.net", data[1]["abuse-mailbox"])
	require.Equal(t, "JV266-RIPE", data[1]["admin-c"])
	require.Equal(t, "EK492-RIPE\nMM611-RIPE\nTB1732-RIPE\nJT3074-RIPE\nLC4380-RIPE\nJS16231-RIPE", data[1]["tech-c"])
	require.Equal(t, "MNET1-RIPE", data[1]["nic-hdl"])
	require.Equal(t, "hostmaster role account", data[1]["remarks"])
	require.Equal(t, "MNET-MNT", data[1]["mnt-by"])
	require.Equal(t, "2002-08-21T10:05:21Z", data[1]["created"])
	require.Equal(t, "2014-12-15T10:11:35Z", data[1]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[1]["source"])

	require.Equal(t, "Joerg Vierke", data[2]["person"])
	require.Equal(t, "M-net Telekommunikations GmbH\nEmmy-Noether-Str. 2\nD-80992 Muenchen\nGermany", data[2]["address"])
	require.Equal(t, "+49 89 45200 5943", data[2]["phone"])
	require.Equal(t, "+49 89 45200 5909", data[2]["fax"])
	require.Equal(t, "JV266-RIPE", data[2]["nic-hdl"])
	require.Equal(t, "PGPKEY-6AC7922A\n-------------------------------------------------\nSPAM or net abuse please mail to abuse@m-net.de\nReports sent to my email address will be ignored.\n-------------------------------------------------", data[2]["remarks"])
	require.Equal(t, "MNET-MNT", data[2]["mnt-by"])
	require.Equal(t, "2001-11-08T17:17:52Z", data[2]["created"])
	require.Equal(t, "2017-10-30T21:44:48Z", data[2]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[2]["source"])

	require.Equal(t, "212.18.0.0/19", data[3]["route"])
	require.Equal(t, "DE-MNET-980227", data[3]["descr"])
	require.Equal(t, "AS8767", data[3]["origin"])
	require.Equal(t, "AS8767-MNT", data[3]["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data[3]["created"])
	require.Equal(t, "2011-02-26T08:19:44Z", data[3]["last-modified"])
	require.Equal(t, "RIPE", data[3]["source"])
}

func TestIP3(t *testing.T) {
	data, err := IP(net.ParseIP("23.8.8.8"))

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 10, len(data))

	require.Equal(t, "23.0.0.0 - 23.15.255.255", data[0]["range"])
	require.Equal(t, "23.0.0.0/12", data[0]["cidr"])
	require.Equal(t, "AKAMAI", data[0]["name"])
	require.Equal(t, "NET-23-0-0-0-1", data[0]["handle"])
	require.Equal(t, "NET23 (NET-23-0-0-0-0)", data[0]["parent"])
	require.Equal(t, "Direct Allocation", data[0]["type"])
	require.Equal(t, "", data[0]["origin-as"])
	require.Equal(t, "Akamai Technologies, Inc. (AKAMAI)", data[0]["organization"])
	require.Equal(t, "2010-12-17", data[0]["reg-date"])
	require.Equal(t, "2012-03-02", data[0]["updated"])
	require.Equal(t, "https://whois.arin.net/rest/net/NET-23-0-0-0-1", data[0]["ref"])

	require.Equal(t, "Akamai Technologies, Inc.", data[1]["organization"])
	require.Equal(t, "AKAMAI", data[1]["id"])
	require.Equal(t, "150 Broadway", data[1]["address"])
	require.Equal(t, "Cambridge", data[1]["city"])
	require.Equal(t, "MA", data[1]["state-province"])
	require.Equal(t, "02142", data[1]["postal-code"])
	require.Equal(t, "US", data[1]["country"])
	require.Equal(t, "1999-01-21", data[1]["reg-date"])
	require.Equal(t, "2017-03-07", data[1]["updated"])
	require.Equal(t, "https://whois.arin.net/rest/org/AKAMAI", data[1]["ref"])

	require.Equal(t, "23.8.0.0 - 23.8.15.255", data[6]["range"])
	require.Equal(t, "23.8.0.0/20", data[6]["cidr"])
	require.Equal(t, "AIBV", data[6]["name"])
	require.Equal(t, "NET-23-8-0-0-1", data[6]["handle"])
	require.Equal(t, "AKAMAI (NET-23-0-0-0-1)", data[6]["parent"])
	require.Equal(t, "Reassigned", data[6]["type"])
	require.Equal(t, "", data[6]["origin-as"])
	require.Equal(t, "Akamai International, BV (AIB-17)", data[6]["organization"])
	require.Equal(t, "2015-06-22", data[6]["reg-date"])
	require.Equal(t, "2015-06-22", data[6]["updated"])
	require.Equal(t, "https://whois.arin.net/rest/net/NET-23-8-0-0-1", data[6]["ref"])

	require.Equal(t, "Akamai International, BV", data[7]["organization"])
	require.Equal(t, "AIB-17", data[7]["id"])
	require.Equal(t, "Prins Bernhardplein 200", data[7]["address"])
	require.Equal(t, "Amsterdam", data[7]["city"])
	require.Equal(t, "", data[7]["state-province"])
	require.Equal(t, "1097 JB", data[7]["postal-code"])
	require.Equal(t, "NL", data[7]["country"])
	require.Equal(t, "2013-09-19", data[7]["reg-date"])
	require.Equal(t, "2016-12-14", data[7]["updated"])
	require.Equal(t, "https://whois.arin.net/rest/org/AIB-17", data[7]["ref"])
}
