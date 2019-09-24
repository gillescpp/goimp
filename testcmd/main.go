package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gillescpp/goimp"
)

func main() {
	user := ""
	password := ""
	if len(os.Args) > 2 {
		user = os.Args[1]
		password = os.Args[2]
	}

	fmt.Println("test impersonation", user, password)

	// test current username
	u, err := goimp.UserName()
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println("current username", u)

	//impersonation to user "test"
	err = goimp.Impersonate(user, password)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// test new username
	u, _ = goimp.UserName()
	fmt.Println("new username", u)

	//revert
	err = goimp.Revert()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// test final username
	u, _ = goimp.UserName()
	fmt.Println("after revert username", u)
}
