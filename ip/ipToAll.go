package ip

import (
	"fmt"

	"github.com/jamesog/iptoasn"
)

func GetAsnDomainCidrForIp(ipInput string)(string,string,string,error) {
	ip, err := iptoasn.LookupIP(ipInput)
	if err != nil {
		return "","","",err
	}

	return fmt.Sprintf("AS%d", ip.ASNum),ip.ASName,ip.BGPPrefix,nil

}
