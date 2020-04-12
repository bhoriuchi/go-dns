package main

import (
	"fmt"

	"github.com/bhoriuchi/go-dns/windns"
)

func main() {
	c, err := windns.NewWindDNSClientWithCredentials(
		xHost,
		xDomain,
		xUsername,
		xPassword,
	)

	if err != nil {
		panic(err)
	}

	defer c.Cleanup()

	r, _, err := c.RemoveA(
		"test2",
		xHost,
		xZone,
		"192.168.2.223",
		300,
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("MSG: %+v", r)
}
