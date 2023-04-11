package main

import (
	"fmt"
	"riskprofiler/asn"
	"riskprofiler/cidr"
	"riskprofiler/domain"
	"riskprofiler/ip"
)

func ASNtoAll() {

	ASN := "AS7018"

	// asn to ips
	ips, err := asn.GetIPAddressesAsStream(ASN)
	if err != nil {
		fmt.Println(err)
	}
	for ip := range ips {
		fmt.Println(ip)
	}

	// asn to cidr
	cidrs, err := asn.GetCIDRsForASNNum(ASN)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(cidrs)

	// asn to domain
	domain, err := asn.GetDomainforASN(ASN)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(domain)
}

func CIDRtoAll() {
	CIDR := "172.0.0.1/16"

	// CIDR to allips
	ips, err := cidr.CIDRtoIps(CIDR)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ips)

	//asn for cidrs
	asn, err := cidr.GetASNForCIDR(CIDR)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(asn)

	//domain for cidrs
	domain, err := cidr.GetDomainForCIDR(CIDR)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(domain)

}

func IpToAll() {
	ipInput := "172.0.0.1"
	asn, domain, cidr, err := ip.GetAsnDomainCidrForIp(ipInput)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(asn, domain, cidr)
}

func DomainToAll() {
	ip, err := domain.LookupIPForDomain("google.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ip)

}

func main() {
	fmt.Println("hii")
	// DomainToAll()
	IpToAll()

}
