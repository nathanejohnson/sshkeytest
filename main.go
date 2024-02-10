package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
)

func main() {
	eeStatus := 0
	fs := flag.NewFlagSet("sshkeytest", flag.ExitOnError)
	fs.IntVar(&eeStatus, "encrypted-exit-status", eeStatus, "exit status for encrypted private keys")
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) != 1 {
		log.Fatalf("usage: %s [keyfile]", os.Args[0])
	}
	k, err := testKey(args[0])
	if err != nil {
		var passMissing *ssh.PassphraseMissingError
		if errors.As(err, &passMissing) {
			fmt.Printf("key is encrypted\n")
			os.Exit(eeStatus)
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
