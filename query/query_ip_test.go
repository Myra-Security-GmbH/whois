package query

import (
	"fmt"
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
	require.Equal(t, "194.25.2.0 - 194.25.3.255", data[0]["inetnum"])
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
	require.Equal(t, "+49 6151 6809399", data[2]["fax-no"])
	require.Equal(t, "DTIP", data[2]["nic-hdl"])
	require.Equal(t, "DTAG-NIC", data[2]["mnt-by"])
	require.Equal(t, "2003-01-29T10:22:59Z", data[2]["created"])
	require.Equal(t, "2015-11-27T08:02:45Z", data[2]["last-modified"])
	require.Equal(t, "RIPE # Filtered", data[2]["source"])

	// record 4
	require.Equal(t, "Security Team", data[3]["person"])
	require.Equal(t, "Deutsche Telekom AG\nDarmstadt, Germany", data[3]["address"])
	require.Equal(t, "+49 180 2 33 1000", data[3]["phone"])
	require.Equal(t, "+49 6151 6809399", data[3]["fax-no"])
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

	require.Equal(t, "212.18.0.0 - 212.18.0.255", data[0]["inetnum"])
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
	require.Equal(t, "+49 89 45200 3984", data[1]["fax-no"])
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
	require.Equal(t, "+49 89 45200 5909", data[2]["fax-no"])
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

	fmt.Printf("%+v\n", data)

	require.Equal(t, 2, len(data))

}

func TestIP4(t *testing.T) {

}
