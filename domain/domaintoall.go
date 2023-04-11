package domain

import "net"

func LookupIPForDomain(domain string) (string, error) {
	// Perform a reverse DNS lookup to get the IP address of the domain
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	ip := ips[0]
	return ip.String(), nil
}
