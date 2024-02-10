package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s [keyfile]", os.Args[1])
	}
	k, err := testKey(os.Args[1])
	if err != nil {
		var passMissing *ssh.PassphraseMissingError
		if errors.As(err, &passMissing) {
			fmt.Printf("key is encrypted")
			return
		}
		log.Fatalf("error processing key: %s", err)
	}
	fmt.Printf("%s key is not encrypted\n", k.Type())
}

func readFile(loc string) ([]byte, error) {
	var (
		payload []byte
		err     error
	)
	if loc == "-" {
		payload, err = io.ReadAll(os.Stdin)
	} else {
		payload, err = os.ReadFile(loc)
	}
	return payload, err
}

func testKey(loc string) (ssh.PublicKey, error) {
	payload, err := readFile(loc)
	if err != nil {
		return nil, err
	}
	crt, err := ssh.ParsePrivateKey(payload)
	if err != nil {
		return nil, err
	}
	return crt.PublicKey(), nil

}
