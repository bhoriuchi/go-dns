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

// Client a dns client for windows dns
type Client struct {
	g        *gss.GSS
	keyname  *string
	client   *tsigclient.Client
	krb5host string
	domain   string
	username string
	password string
	kdcs     []string
}

// NegotiateContext obtains a new tkey
func (c *Client) NegotiateContext() (err error) {
	var cfg *config.Config

	// clean up existing
	if c.g != nil || c.keyname != nil {
		c.Cleanup()
	}

	if c.g, err = gss.New(); err != nil {
		return
	}

	// if no kdcs, use the host
	if c.kdcs == nil || len(c.kdcs) == 0 {
		c.kdcs = []string{c.krb5host}
	}

	if cfg, err = NewKrb5Config(c.domain, c.kdcs); err != nil {
		return
	}

	cl := client.NewWithPassword(c.username, c.domain, c.password, cfg, client.DisablePAFXFAST(true))
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

// Exchange performs an exchange
func (c *Client) Exchange(host, zone string, msg *dns.Msg) (r *dns.Msg, tt time.Duration, err error) {
	r, tt, err = c.client.Exchange(msg, net.JoinHostPort(host, "53"))
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("DNS error: %s (%d)", dns.RcodeToString[r.Rcode], r.Rcode)
		return
	}

	return
}

// NewWindDNSClientWithCredentials creates a new client
func NewWindDNSClientWithCredentials(krb5host, domain, username, password string, kdcs ...string) (c *Client, err error) {
	c = &Client{
		krb5host: krb5host,
		domain:   domain,
		username: username,
		password: password,
		kdcs:     kdcs,
	}

	err = c.NegotiateContext()
	return
}
