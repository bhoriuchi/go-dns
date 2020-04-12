package windns

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ns1/tsig"
)

// InsertA inserts an A record
func (c *Client) InsertA(name, host, zone, address string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	var rr dns.RR
	msg := new(dns.Msg)

	fqdn := fmt.Sprintf(
		"%s.%s",
		strings.Trim(name, "."),
		strings.Trim(zone, "."),
	)

	if rr, err = dns.NewRR(fmt.Sprintf("%s %d A %s", dns.Fqdn(fqdn), ttl, address)); err != nil {
		return
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Insert([]dns.RR{rr})
	msg.SetTsig(*c.keyname, tsig.GSS, 300, time.Now().Unix())

	r, tt, err = c.Exchange(host, zone, msg)
	return
}

// RemoveA removes an A record
func (c *Client) RemoveA(name, host, zone, address string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	var rr dns.RR
	msg := new(dns.Msg)

	fqdn := fmt.Sprintf(
		"%s.%s",
		strings.Trim(name, "."),
		strings.Trim(zone, "."),
	)

	if rr, err = dns.NewRR(fmt.Sprintf("%s %d A %s", dns.Fqdn(fqdn), ttl, address)); err != nil {
		return
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Remove([]dns.RR{rr})
	msg.SetTsig(*c.keyname, tsig.GSS, 300, time.Now().Unix())

	r, tt, err = c.Exchange(host, zone, msg)
	return
}

// UpdateA updates an A record
func (c *Client) UpdateA(name, host, zone, oAddress, nAddress string, ttl int) (r *dns.Msg, tt time.Duration, err error) {
	var orr dns.RR
	var nrr dns.RR
	msg := new(dns.Msg)

	fqdn := fmt.Sprintf(
		"%s.%s",
		strings.Trim(name, "."),
		strings.Trim(zone, "."),
	)

	if orr, err = dns.NewRR(fmt.Sprintf("%s %d A %s", dns.Fqdn(fqdn), ttl, oAddress)); err != nil {
		return
	}

	if nrr, err = dns.NewRR(fmt.Sprintf("%s %d A %s", dns.Fqdn(fqdn), ttl, nAddress)); err != nil {
		return
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Remove([]dns.RR{orr})
	msg.Insert([]dns.RR{nrr})
	msg.SetTsig(*c.keyname, tsig.GSS, 300, time.Now().Unix())

	r, tt, err = c.Exchange(host, zone, msg)
	return
}
