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

	r, _, err := c.InsertCNAME(
		"test4",
		xHost,
		xZone,
		"test3.example.com",
		300,
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("MSG: %+v", r)
}
