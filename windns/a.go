package windns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// InsertA inserts an A record
func (c *Client) InsertA(name, host, zone, address string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	req := fmt.Sprintf("%s %d A %s", fqdnJoin(name, zone), ttl, address)
	r, tt, err = c.Insert(host, zone, []string{req})
	return
}

// RemoveA removes an A record
func (c *Client) RemoveA(name, host, zone, address string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	req := fmt.Sprintf("%s %d A %s", fqdnJoin(name, zone), ttl, address)
	r, tt, err = c.Remove(host, zone, []string{req})
	return
}

// UpdateA updates an A record
func (c *Client) UpdateA(name, host, zone, oAddress, nAddress string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	nReq := fmt.Sprintf("%s %d A %s", fqdnJoin(name, zone), ttl, nAddress)
	oReq := fmt.Sprintf("%s %d A %s", fqdnJoin(name, zone), ttl, oAddress)
	r, tt, err = c.Update(host, zone, []string{oReq}, []string{nReq})
	return
}
