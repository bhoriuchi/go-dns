package main

import (
	"fmt"

	"github.com/bhoriuchi/go-dns/windns"
)

func main() {
	c, err := windns.NewClient(&windns.ClientConfig{
		KRB5Host: xHost,
		Domain:   xDomain,
		Username: xUsername,
		Password: xPassword,
	})

	if err != nil {
		panic(err)
	}

	defer c.Cleanup()

	/*
		r, _, err := c.InsertCNAME(
			xHost,
			"test4",
			xZone,
			"test3.example.com",
			300,
		)
	*/
	data, _, _, err := c.Lookup(
		xHost,
		fmt.Sprintf("test4.%s", xZone),
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("MSG: %s\n", data)
}
