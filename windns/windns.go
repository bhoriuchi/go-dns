package windns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ns1/gokrb5/v8/client"
	"github.com/ns1/gokrb5/v8/config"
	"github.com/ns1/tsig"
	tsigclient "github.com/ns1/tsig/client"
	"github.com/ns1/tsig/gss"
)

// NewKrb5Config creates a new krb5 config
func NewKrb5Config(domain string, kdcs []string) (*config.Config, error) {
	if len(kdcs) == 0 {
		return nil, fmt.Errorf("no kdcs specified")
	}

	ld := strings.ToLower(domain)
	ud := strings.ToUpper(domain)
	kdcarr := []string{}
	for _, kdc := range kdcs {
		kdcarr = append(kdcarr, fmt.Sprintf("kdc = %s", kdc))
	}

	krb5conf := fmt.Sprintf(`[libdefaults]
default_realm = %s
udp_preference_limit = 1
forwardable = true
[realms]
%s = {
%s
default_domain = %s
}
[domain_realm]
.%s=%s
%s=%s`, ud, ud, strings.Join(kdcarr, "\n"), ld, ld, ud, ld, ud)

	return config.NewFromString(krb5conf)
}

// ClientOption a client option
type ClientOption func(cl *Client) (err error)

// Client a dns client for windows dns
type Client struct {
	g        *gss.GSS
	keyname  *string
	client   *tsigclient.Client
	krb5conf *config.Config
	krb5host string
	domain   string
	username string
	password string
}

// ClientConfig .
type ClientConfig struct {
	KRB5Host string
	KRB5Conf *config.Config
	Domain   string
	Username string
	Password string
}

// NewClient creates a new client
func NewClient(conf *ClientConfig, opts ...ClientOption) (c *Client, err error) {
	if len(conf.KRB5Host) == 0 {
		err = fmt.Errorf("missing required configuration for krb5host")
		return
	} else if len(conf.Domain) == 0 {
		err = fmt.Errorf("missing required configuration for domain")
		return
	} else if len(conf.Username) == 0 {
		err = fmt.Errorf("missing required configuration for username")
		return
	} else if len(conf.Password) == 0 {
		err = fmt.Errorf("missing required configuration for password")
		return
	}

	c = &Client{
		krb5host: conf.KRB5Host,
		krb5conf: conf.KRB5Conf,
		domain:   conf.Domain,
		username: conf.Username,
		password: conf.Password,
	}

	for _, opt := range opts {
		if err = opt(c); err != nil {
			return
		}
	}

	if c.krb5conf == nil {
		if c.krb5conf, err = NewKrb5Config(c.domain, []string{c.krb5host}); err != nil {
			return
		}
	}

	err = c.NegotiateContext()
	return
}

// WithKRB5ConfigString sets the krb5 config
func WithKRB5ConfigString(conf string) ClientOption {
	return func(c *Client) (err error) {
		c.krb5conf, err = config.NewFromString(conf)
		return
	}
}

// WithKRB5ConfigData generates the krb5 config
func WithKRB5ConfigData(domain string, kdcs []string) ClientOption {
	return func(c *Client) (err error) {
		c.krb5conf, err = NewKrb5Config(domain, kdcs)
		return
	}
}

// Keyname returns the keyname
func (c *Client) Keyname() *string {
	return c.keyname
}

// NegotiateContext obtains a new tkey
func (c *Client) NegotiateContext() (err error) {
	// clean up existing
	if c.g != nil || c.keyname != nil {
		c.Cleanup()
	}

	if c.g, err = gss.New(); err != nil {
		return
	}

	cl := client.NewWithPassword(c.username, c.domain, c.password, c.krb5conf, client.DisablePAFXFAST(true))
	if c.keyname, _, err = c.g.NegotiateContextWithClient(c.krb5host, cl); err != nil {
		return
	}

	c.client = &tsigclient.Client{
		TsigAlgorithm: map[string]*tsigclient.TsigAlgorithm{
			tsig.GSS: {
				Generate: c.g.GenerateGSS,
				Verify:   c.g.VerifyGSS,
			},
		},
	}

	c.client.TsigSecret = map[string]string{*c.keyname: ""}
	return
}

// Cleanup cleans up the client
func (c *Client) Cleanup() (err error) {
	if err = c.g.DeleteContext(c.keyname); err != nil {
		return
	}

	return
}

// Insert performs an insert
func (c *Client) Insert(host, zone string, reqs []string) (r *dns.Msg, tt time.Duration, err error) {
	msg := new(dns.Msg)
	updates := []dns.RR{}

	for _, req := range reqs {
		var rr dns.RR
		if rr, err = dns.NewRR(req); err != nil {
			return
		}
		updates = append(updates, rr)
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Insert(updates)

	r, tt, err = c.Exchange(host, msg)
	return
}

// Remove performs a remove
func (c *Client) Remove(host, zone string, reqs []string) (r *dns.Msg, tt time.Duration, err error) {
	msg := new(dns.Msg)
	updates := []dns.RR{}

	for _, req := range reqs {
		var rr dns.RR
		if rr, err = dns.NewRR(req); err != nil {
			return
		}
		updates = append(updates, rr)
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Remove(updates)

	r, tt, err = c.Exchange(host, msg)
	return
}

// Update performs an update
func (c *Client) Update(host, zone string, oReqs, nReqs []string) (r *dns.Msg, tt time.Duration, err error) {
	msg := new(dns.Msg)
	oUpdates := []dns.RR{}
	nUpdates := []dns.RR{}

	for _, req := range oReqs {
		var rr dns.RR
		if rr, err = dns.NewRR(req); err != nil {
			return
		}
		oUpdates = append(oUpdates, rr)
	}

	for _, req := range nReqs {
		var rr dns.RR
		if rr, err = dns.NewRR(req); err != nil {
			return
		}
		nUpdates = append(nUpdates, rr)
	}

	msg.SetUpdate(dns.Fqdn(zone))
	msg.Remove(oUpdates)
	msg.Insert(nUpdates)

	r, tt, err = c.Exchange(host, msg)
	return
}

// Lookup looks up a value
func (c *Client) Lookup(host, value string) (data string, r *dns.Msg, tt time.Duration, err error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(value), dns.TypeANY)
	r, tt, err = c.Exchange(host, msg)

	if len(r.Answer) == 0 {
		return
	}

	data = strings.Trim(dns.Field(r.Answer[0], 1), ".")
	return
}

// Exchange performs an exchange
func (c *Client) Exchange(host string, msg *dns.Msg) (r *dns.Msg, tt time.Duration, err error) {
	msg.SetTsig(*c.Keyname(), tsig.GSS, 300, time.Now().Unix())

	r, tt, err = c.client.Exchange(msg, net.JoinHostPort(host, "53"))
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("DNS error: %s (%d)", dns.RcodeToString[r.Rcode], r.Rcode)
		return
	}

	return
}

// FQDNJoin joins the name and zone to create an fqdn
func fqdnJoin(name, zone string) (fqdn string) {
	fqdn = dns.Fqdn(fmt.Sprintf(
		"%s.%s",
		strings.Trim(name, "."),
		strings.Trim(zone, "."),
	))
	return
}
