package main

import (
	"fmt"
	"log"
	"net"

	"github.com/jamesog/iptoasn"
	"github.com/projectdiscovery/ipranger"

	// "github.com/projectdiscovery/asnmap"
	// "github.com/osrg/gobgp/packet"
	// "github.com/maxmind/geoip2"
	"github.com/ammario/ipisp"
)

// ip to all
func IpToAsn(ipInput string) {
	// ipInput := "172.0.0.1"
	fmt.Println(ipInput)
	ip, err := iptoasn.LookupIP(ipInput)
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println("ASn-NAme", ip.ASName, "\n", "Asn", ip.ASNum, "\n", "CIDR", ip.BGPPrefix)

}

// func AsnToIp() {
// 	asnInput := "20712"

// asn, err := iptoasn.LookupASN(asnInput)
// if err != nil {
// 	fmt.Println("Error:", err)
// }
// fmt.Println(asn.ASName)
// _, n, _ := ipaddr.Lookup(fmt.Sprintf("AS%d", asnInput))
// fmt.Println(n.String())

// fmt.Println(asn)
// prefixes, err := iplib.LookupPrefixes(fmt.Sprintf("AS%d", asnInput))
// if err != nil {
// 	fmt.Println(err)
// }
// for _, prefix := range prefixes {
// 	fmt.Println(prefix.String())
// }

// }

// cidr to iprange
func AsRangeToIpRange() {
	asrange := "172.0.0.1/16"
	ips, err := ipranger.Ips(asrange)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips[0], "-to", ips[len(ips)-1])

	IpToAsn(ips[1])

	// IpToAsn(ips[15])

}

// func domainToIp(){
// 	domain := "hackerone.com"
// 	resolvedIps, err := asnmap.ResolveDomain(domain)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	for _, ip := range resolvedIps {

// 	}

// }

func main() {

	// IpToAsn()

	// AsnToIp()

	// AsRangeToIpRange()
	// mainAsntoIp()
	// IOu()
	IpToAsn1()
}

//  func AsnToIp() {
// 	// Replace AS_NUMBER with the ASN you want to convert
// 	asn := uint32(7018)

// 	// Create a new BGP update message with the AS_PATH attribute set to the ASN
// 	update := &bgp.BGPUpdate{
// 		PathAttributes: []bgp.PathAttributeInterface{
// 			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
// 				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{asn}),
// 			}),
// 		},
// 	}

// 	// Get the first reachable IP address for the ASN
// 	ip, err := getFirstIPAddressForASN(update)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	fmt.Printf("IP address for ASN %d: %s\n", asn, ip.String())
// }

// func getFirstIPAddressForASN(update *bgp.BGPUpdate) (net.IP, error) {
// 	// Create a new BGP update message that requests the first IP address for the given ASN
// 	request := &bgp.PathFetchRequest{
// 		Query: []bgp.PathQuery{
// 			bgp.PathQuery{
// 				Type:      bgp.BGP_PATH_ATTR_TYPE_AS_PATH,
// 				MatchType: bgp.BGP_PATH_ATTR_MATCH_TYPE_EQUAL,
// 				Value: &bgp.AsPathAttribute{
// 					[]bgp.AsPathParamInterface{
// 						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{asn}),
// 					},
// 				},
// 			},
// 			bgp.PathQuery{
// 				Type:      bgp.BGP_PATH_ATTR_TYPE_NEXT_HOP,
// 				MatchType: bgp.BGP_PATH_ATTR_MATCH_TYPE_EXISTS,
// 			},
// 		},
// 		AttributeMask: bgp.ROUTE_ATTR_ALL_WITHDRAW,
// 	}

// 	// Execute the BGP update message and get the first reachable IP address
// 	res, err := bgp.ProcessMessage(update, request)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if len(res) == 0 {
// 		return nil, fmt.Errorf("no IP address found for ASN %d", asn)
// 	}

// 	// Return the first reachable IP address
// 	return res[0].GetNlri().GetPrefix().GetIP(), nil
// }

// func mainAsntoIp() {
// 	asn := 3356 // Replace with the ASN you want to look up

// 	db, err := geoip2.Open("GeoLite2-ASN.mmdb")
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	defer db.Close()

// 	ipNet, err := db.ASN(net.ParseIP(fmt.Sprintf("2001:db8::/32")))
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	if ipNet.AutonomousSystemNumber != asn {
// 		fmt.Printf("ASN %d not found\n", asn)
// 		return
// 	}

// 	fmt.Println(ipNet.Network.String())
// }

// func mainojj() {
// 	asn := 3356 // Replace with the ASN you want to look up

// 	// db, err := geoip2.Open("GeoLite2-ASN.mmdb")
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	defer db.Close()

// 	record, err := db.ASN(net.ParseIP("8.8.8.8"))
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	if record.AutonomousSystemNumber != asn {
// 		fmt.Printf("ASN %d not found\n", asn)
// 		return
// 	}

//		fmt.Printf("AS Name: %s\n", record.AutonomousSystemOrganization)
//		fmt.Printf("IP Range: %s - %s\n", record.Network.String(), record.Network.Last().String())
//	}
func IOu() {

	client, err := ipisp.NewDNSClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.LookupIP(net.ParseIP("4.2.2.2"))
	if err != nil {
		log.Fatalf("Error looking up 4.2.2.2: %v", err)
	}
	fmt.Printf("Resolved IP 4.2.2.2: %+v\n", resp)

	resp, err = client.LookupASN(ipisp.ASN(666))
	if err != nil {
		log.Fatalf("Failed to lookup ASN 666: %v", err)
	}
	fmt.Printf("Resolved ASN 666: %+v\n", resp)
}

func IpToAsn1(){
	ipInput := "172.98.9.255"

ip, err := iptoasn.LookupIP(ipInput)
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println("ASn-NAme", ip.ASName, "\n", "Asn", ip.ASNum, "\n", "CIDR", ip.BGPPrefix)

}