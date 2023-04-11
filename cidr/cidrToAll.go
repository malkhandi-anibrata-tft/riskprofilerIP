package cidr

import (
	"fmt"
	"net"

	"github.com/jamesog/iptoasn"
	"github.com/projectdiscovery/ipranger"
)

func CIDRtoIps(value string) ([]string, error) {
	ips, err := ipranger.Ips(value)
	if err != nil {
		return make([]string, 0), nil
	}
	return ips, nil

}

func GetASNForCIDR(cidr string) (string, error) {
	// Extract the IP address from the CIDR block
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	resASN, err := iptoasn.LookupIP(ip.String())
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("AS%d", resASN.ASNum), nil

}

func GetDomainForCIDR(cidr string) (string, error) {
	// Extract the IP address from the CIDR block
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	resASN, err := iptoasn.LookupIP(ip.String())
	if err != nil {
		return "", err
	}

	return resASN.ASName, nil

}
