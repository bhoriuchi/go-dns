package windns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// InsertCNAME inserts an CNAME record
func (c *Client) InsertCNAME(host, name, zone, target string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	req := fmt.Sprintf("%s %d CNAME %s", fqdnJoin(name, zone), ttl, dns.Fqdn(target))
	r, tt, err = c.Insert(host, zone, []string{req})
	return
}

// RemoveCNAME removes an CNAME record
func (c *Client) RemoveCNAME(host, name, zone, target string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	req := fmt.Sprintf("%s %d CNAME %s", fqdnJoin(name, zone), ttl, dns.Fqdn(target))
	r, tt, err = c.Remove(host, zone, []string{req})
	return
}

// UpdateCNAME updates an CNAME record
func (c *Client) UpdateCNAME(host, name, zone, oTarget, nTarget string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	nReq := fmt.Sprintf("%s %d CNAME %s", fqdnJoin(name, zone), ttl, dns.Fqdn(nTarget))
	oReq := fmt.Sprintf("%s %d CNAME %s", fqdnJoin(name, zone), ttl, dns.Fqdn(oTarget))
	r, tt, err = c.Update(host, zone, []string{oReq}, []string{nReq})
	return
}
