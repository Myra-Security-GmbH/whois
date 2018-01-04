// +build !testing

package whois

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIP1(t *testing.T) {

	data, err := IP(net.ParseIP("194.25.2.129"), nil)

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 5, len(data.Records()))

	// record 1
	require.Equal(t, "194.25.2.0 - 194.25.3.255", data.Records()[0].data["range"])
	require.Equal(t, "DTAG-ONLINE1", data.Records()[0].data["netname"])
	require.Equal(t, "Deutsche Telekom AG", data.Records()[0].data["descr"])
	require.Equal(t, "ORG-DTAG1-RIPE", data.Records()[0].data["org"])
	require.Equal(t, "DE", data.Records()[0].data["country"])
	require.Equal(t, "DTIP", data.Records()[0].data["admin-c"])
	require.Equal(t, "DTST", data.Records()[0].data["tech-c"])
	require.Equal(t, "ASSIGNED PA", data.Records()[0].data["status"])
	require.Equal(t, "DTAG-NIC", data.Records()[0].data["mnt-by"])
	require.Equal(t, "2002-01-08T09:31:19Z", data.Records()[0].data["created"])
	require.Equal(t, "2014-06-18T09:38:18Z", data.Records()[0].data["last-modified"])
	require.Equal(t, "RIPE", data.Records()[0].data["source"])

	// record 2
	require.Equal(t, "ORG-DTAG1-RIPE", data.Records()[1].data["organisation"])
	require.Equal(t, "Deutsche Telekom AG", data.Records()[1].data["org-name"])
	require.Equal(t, "OTHER", data.Records()[1].data["org-type"])
	require.Equal(t, "Group Information Security, SDA/Abuse\nT-Online-Allee 1\nDE 64295 Darmstadt", data.Records()[1].data["address"])
	require.Equal(t, "abuse contact in case of Spam, hack attacks, illegal activity, violation, scans, probes, etc.", data.Records()[1].data["remarks"])
	require.Equal(t, "DTAG-NIC", data.Records()[1].data["mnt-ref"])
	require.Equal(t, "DTAG-NIC", data.Records()[1].data["mnt-by"])
	require.Equal(t, "DTAG4-RIPE", data.Records()[1].data["abuse-c"])
	require.Equal(t, "2014-06-17T11:47:04Z", data.Records()[1].data["created"])
	require.Equal(t, "2014-06-17T11:47:04Z", data.Records()[1].data["last-modified"])
	require.Equal(t, "RIPE # Filtered", data.Records()[1].data["source"])

	// record 3
	require.Equal(t, "DTAG Global IP-Addressing", data.Records()[2].data["person"])
	require.Equal(t, "Deutsche Telekom AG\nDarmstadt, Germany", data.Records()[2].data["address"])
	require.Equal(t, "+49 180 2 33 1000", data.Records()[2].data["phone"])
	require.Equal(t, "+49 6151 6809399", data.Records()[2].data["fax"])
	require.Equal(t, "DTIP", data.Records()[2].data["nic-hdl"])
	require.Equal(t, "DTAG-NIC", data.Records()[2].data["mnt-by"])
	require.Equal(t, "2003-01-29T10:22:59Z", data.Records()[2].data["created"])
	require.Equal(t, "2015-11-27T08:02:45Z", data.Records()[2].data["last-modified"])
	require.Equal(t, "RIPE # Filtered", data.Records()[2].data["source"])

	// record 4
	require.Equal(t, "Security Team", data.Records()[3].data["person"])
	require.Equal(t, "Deutsche Telekom AG\nDarmstadt, Germany", data.Records()[3].data["address"])
	require.Equal(t, "+49 180 2 33 1000", data.Records()[3].data["phone"])
	require.Equal(t, "+49 6151 6809399", data.Records()[3].data["fax"])
	require.Equal(t, "DTST", data.Records()[3].data["nic-hdl"])
	require.Equal(t, "DTAG-NIC", data.Records()[3].data["mnt-by"])
	require.Equal(t, "2003-01-29T10:31:11Z", data.Records()[3].data["created"])
	require.Equal(t, "2015-11-27T08:03:38Z", data.Records()[3].data["last-modified"])
	require.Equal(t, "RIPE # Filtered", data.Records()[3].data["source"])

	// record 5
	require.Equal(t, "194.25.0.0/16", data.Records()[4].data["route"])
	require.Equal(t, "Deutsche Telekom AG, Internet service provider", data.Records()[4].data["descr"])
	require.Equal(t, "AS3320", data.Records()[4].data["origin"])
	require.Equal(t, "AS3320:RS-PA-TELEKOM", data.Records()[4].data["member-of"])
	require.Equal(t, "DTAG-RR", data.Records()[4].data["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data.Records()[4].data["created"])
	require.Equal(t, "2004-06-15T17:32:45Z", data.Records()[4].data["last-modified"])
	require.Equal(t, "RIPE", data.Records()[4].data["source"])

}

func TestIP2(t *testing.T) {
	data, err := IP(net.ParseIP("212.18.0.5"), nil)

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 4, len(data.Records()))

	require.Equal(t, "212.18.0.0 - 212.18.0.255", data.Records()[0].data["range"])
	require.Equal(t, "MNET", data.Records()[0].data["netname"])
	require.Equal(t, "M-net Telekommunikations GmbH", data.Records()[0].data["descr"])
	require.Equal(t, "DE", data.Records()[0].data["country"])
	require.Equal(t, "JV266-RIPE", data.Records()[0].data["admin-c"])
	require.Equal(t, "MNET1-RIPE", data.Records()[0].data["tech-c"])
	require.Equal(t, "ASSIGNED PA", data.Records()[0].data["status"])
	require.Equal(t, "MNET-MNT", data.Records()[0].data["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data.Records()[0].data["created"])
	require.Equal(t, "2006-07-28T12:57:53Z", data.Records()[0].data["last-modified"])
	require.Equal(t, "RIPE", data.Records()[0].data["source"])

	require.Equal(t, "Hostmaster Role-Account", data.Records()[1].data["role"])
	require.Equal(t, "M-net Telekommunikations GmbH\nEmmy-Noether-Str. 2\nD-80992 Muenchen\nGermany", data.Records()[1].data["address"])
	require.Equal(t, "+49 89 45200 5907", data.Records()[1].data["phone"])
	require.Equal(t, "+49 89 45200 3984", data.Records()[1].data["fax"])
	require.Equal(t, "abuse@m-online.net", data.Records()[1].data["abuse-mailbox"])
	require.Equal(t, "JV266-RIPE", data.Records()[1].data["admin-c"])
	require.Equal(t, "EK492-RIPE\nMM611-RIPE\nTB1732-RIPE\nJT3074-RIPE\nLC4380-RIPE\nJS16231-RIPE", data.Records()[1].data["tech-c"])
	require.Equal(t, "MNET1-RIPE", data.Records()[1].data["nic-hdl"])
	require.Equal(t, "hostmaster role account", data.Records()[1].data["remarks"])
	require.Equal(t, "MNET-MNT", data.Records()[1].data["mnt-by"])
	require.Equal(t, "2002-08-21T10:05:21Z", data.Records()[1].data["created"])
	require.Equal(t, "2014-12-15T10:11:35Z", data.Records()[1].data["last-modified"])
	require.Equal(t, "RIPE # Filtered", data.Records()[1].data["source"])

	require.Equal(t, "Joerg Vierke", data.Records()[2].data["person"])
	require.Equal(t, "M-net Telekommunikations GmbH\nEmmy-Noether-Str. 2\nD-80992 Muenchen\nGermany", data.Records()[2].data["address"])
	require.Equal(t, "+49 89 45200 5943", data.Records()[2].data["phone"])
	require.Equal(t, "+49 89 45200 5909", data.Records()[2].data["fax"])
	require.Equal(t, "JV266-RIPE", data.Records()[2].data["nic-hdl"])
	require.Equal(t, "PGPKEY-6AC7922A\n-------------------------------------------------\nSPAM or net abuse please mail to abuse@m-net.de\nReports sent to my email address will be ignored.\n-------------------------------------------------", data.Records()[2].data["remarks"])
	require.Equal(t, "MNET-MNT", data.Records()[2].data["mnt-by"])
	require.Equal(t, "2001-11-08T17:17:52Z", data.Records()[2].data["created"])
	require.Equal(t, "2017-10-30T21:44:48Z", data.Records()[2].data["last-modified"])
	require.Equal(t, "RIPE # Filtered", data.Records()[2].data["source"])

	require.Equal(t, "212.18.0.0/19", data.Records()[3].data["route"])
	require.Equal(t, "DE-MNET-980227", data.Records()[3].data["descr"])
	require.Equal(t, "AS8767", data.Records()[3].data["origin"])
	require.Equal(t, "AS8767-MNT", data.Records()[3].data["mnt-by"])
	require.Equal(t, "1970-01-01T00:00:00Z", data.Records()[3].data["created"])
	require.Equal(t, "2011-02-26T08:19:44Z", data.Records()[3].data["last-modified"])
	require.Equal(t, "RIPE", data.Records()[3].data["source"])
}

func TestIP3(t *testing.T) {
	data, err := IP(net.ParseIP("23.8.8.8"), nil)

	require.Nil(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 10, len(data.Records()))

	require.Equal(t, "23.0.0.0 - 23.15.255.255", data.Records()[0].data["range"])
	require.Equal(t, "23.0.0.0/12", data.Records()[0].data["cidr"])
	require.Equal(t, "AKAMAI", data.Records()[0].data["name"])
	require.Equal(t, "NET-23-0-0-0-1", data.Records()[0].data["handle"])
	require.Equal(t, "NET23 (NET-23-0-0-0-0)", data.Records()[0].data["parent"])
	require.Equal(t, "Direct Allocation", data.Records()[0].data["type"])
	require.Equal(t, "", data.Records()[0].data["origin-as"])
	require.Equal(t, "Akamai Technologies, Inc. (AKAMAI)", data.Records()[0].data["organization"])
	require.Equal(t, "2010-12-17", data.Records()[0].data["reg-date"])
	require.Equal(t, "2012-03-02", data.Records()[0].data["updated"])
	require.Equal(t, "https://whois.arin.net/rest/net/NET-23-0-0-0-1", data.Records()[0].data["ref"])

	require.Equal(t, "Akamai Technologies, Inc.", data.Records()[1].data["organization"])
	require.Equal(t, "AKAMAI", data.Records()[1].data["id"])
	require.Equal(t, "150 Broadway", data.Records()[1].data["address"])
	require.Equal(t, "Cambridge", data.Records()[1].data["city"])
	require.Equal(t, "MA", data.Records()[1].data["state-province"])
	require.Equal(t, "02142", data.Records()[1].data["postal-code"])
	require.Equal(t, "US", data.Records()[1].data["country"])
	require.Equal(t, "1999-01-21", data.Records()[1].data["reg-date"])
	require.Equal(t, "2017-03-07", data.Records()[1].data["updated"])
	require.Equal(t, "https://whois.arin.net/rest/org/AKAMAI", data.Records()[1].data["ref"])

	require.Equal(t, "23.8.0.0 - 23.8.15.255", data.Records()[6].data["range"])
	require.Equal(t, "23.8.0.0/20", data.Records()[6].data["cidr"])
	require.Equal(t, "AIBV", data.Records()[6].data["name"])
	require.Equal(t, "NET-23-8-0-0-1", data.Records()[6].data["handle"])
	require.Equal(t, "AKAMAI (NET-23-0-0-0-1)", data.Records()[6].data["parent"])
	require.Equal(t, "Reassigned", data.Records()[6].data["type"])
	require.Equal(t, "", data.Records()[6].data["origin-as"])
	require.Equal(t, "Akamai International, BV (AIB-17)", data.Records()[6].data["organization"])
	require.Equal(t, "2015-06-22", data.Records()[6].data["reg-date"])
	require.Equal(t, "2015-06-22", data.Records()[6].data["updated"])
	require.Equal(t, "https://whois.arin.net/rest/net/NET-23-8-0-0-1", data.Records()[6].data["ref"])

	require.Equal(t, "Akamai International, BV", data.Records()[7].data["organization"])
	require.Equal(t, "AIB-17", data.Records()[7].data["id"])
	require.Equal(t, "Prins Bernhardplein 200", data.Records()[7].data["address"])
	require.Equal(t, "Amsterdam", data.Records()[7].data["city"])
	require.Equal(t, "", data.Records()[7].data["state-province"])
	require.Equal(t, "1097 JB", data.Records()[7].data["postal-code"])
	require.Equal(t, "NL", data.Records()[7].data["country"])
	require.Equal(t, "2013-09-19", data.Records()[7].data["reg-date"])
	require.Equal(t, "2016-12-14", data.Records()[7].data["updated"])
	require.Equal(t, "https://whois.arin.net/rest/org/AIB-17", data.Records()[7].data["ref"])
}
