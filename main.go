package main

import (
	"bufio"
	"fmt"
	"github.com/docopt/docopt.go"
	"github.com/sour-is/bip38tool/gopass"
	"github.com/sour-is/bitcoin/address"
	"log"
	"os"
	"strconv"
	"strings"
)

var APP_NAME string = "BIP38 Encryption Tool"
var APP_USAGE string = `BIP38 Encryption Tool
Copyright (c) 2013, Jon Lundy <jon@xuu.cc> 1NvmHfSjPq1UB9scXFhYDLkihnu9nkQ8xg

Usage:
  bip38tool encrypt [-d]  batch
  bip38tool encrypt [-cp] new [--count=N]
  bip38tool encrypt [-cp] <privatekey>
  
  bip38tool decrypt batch
  bip38tool decrypt <privatekey>

Encrypt Modes:
  <privatekey>  Encrypt the given key.
  new           Generate and encrypt new key.
  batch         Read from stdin and encrypt with passphrase set in environment.

Decrypt Modes:
  <privatekey>  Decrypt the given key.
  batch         Read from stdin and decrypt with passphrase set in environment.

Options:
  --count=N      Number of new keys to generate [default: 1].
  -c,--csv       Output in CSV format.
  -d,--detail    Output in Detail format.
  -p,--ask-pass  Ask for the passphrase instead of using environment variable.
  -h             Usage Help

Environment:
  BIP38_PASS    Passphrase value to use.
  
Examples: 
  bip38tool encrypt -p 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS
  
  BIP38_PASS=secret bip38tool encrypt new
  
  cat keyfile | BIP38_PASS=secret bip38tool encrypt batch
  
  The keyfile is a list of private keys one per line in hex or base58 format. 

  BIP38_PASS=secret bip38tool decrypt 6PRQ7ivF6rFMn1wc7z6w1ZfFsKh4EAY1mhF3gCYkw8PLRMwfZNVqeqmW3F
  
Using OpenSSL for key generation:

  While the tool will use a secure random generator, if you would like to use one that 
  was generated using a different tool that is an option. 

  If using openssl for the key generation generate a random seed to ensure it has
  the highest quality entropy. (see: http://crypto.stackexchange.com/questions/9412/)

    dd if=/dev/random bs=1 count=1024 of=rndfile
    RANDFILE=rndfile openssl ecparam -genkey -name secp256k1 -outform DER | xxd -p -c 125 | cut -c 29-92
`

var arguments map[string]interface{}

type Message struct {
	Priv  *address.PrivateKey
	Bip38 *address.BIP38Key
}

// Initialize application state.
func init() {
	var err error

	arguments, err = docopt.Parse(APP_USAGE, nil, true, APP_NAME, false)
	if err != nil {
		log.Fatal(err)
	}

	// Batch mode does not work with password prompt.
	// Docopt causes it to fall through as a <privatekey>
	if arguments["<privatekey>"] == "batch" {
		arguments["--ask-pass"] = false
		arguments["batch"] = true
	}

	if arguments["--ask-pass"] == true {
		value, err := gopass.GetPass("Enter Passphrase:")
		if err != nil {
			log.Fatal(err)
		}

		repeat, err := gopass.GetPass("Verify Passphrase:")
		if err != nil {
			log.Fatal(err)
		}

		if value != repeat {
			log.Fatal("Passphrase does not match!")
		}

		arguments["<passphrase>"] = value
	} else {
		value := os.Getenv("BIP38_PASS")
		if value == "" {
			log.Fatal("Environment Variable BIP38_PASS not found!")
		}

		arguments["<passphrase>"] = value
	}

	// Batch mode defaults to CSV
	if arguments["batch"] == true && arguments["--detail"] == false {
		arguments["--csv"] = true
	}

}

func main() {

	pass := arguments["<passphrase>"].(string)

	var done chan int
	var in chan string
	var out chan *Message

	if arguments["encrypt"] == true {
		in, out = encrypter(pass)
	} else if arguments["decrypt"] == true {
		in, out = decrypter(pass)
	}

	if arguments["--csv"] == true {
		done = writerCSV(out)
	} else {
		done = writerDetail(out)
	}

	if arguments["encrypt"] == true && arguments["new"] == true {
		n := 1
		if arguments["--count"] != nil {
			n, _ = strconv.Atoi(arguments["--count"].(string))
		}

		for ; n > 0; n-- {
			in <- ""
		}
		close(in)
	} else if arguments["batch"] == true {
		reader := bufio.NewReader(os.Stdin)

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			line = strings.TrimSpace(line)
			if err != nil {
				log.Fatal(err)
			}

			in <- line
		}
		close(in)

	} else {
		line := strings.TrimSpace(arguments["<privatekey>"].(string))

		in <- line
		close(in)
	}

	<-done
}

func encrypter(pass string) (in chan string, out chan *Message) {

	in = make(chan string)
	out = make(chan *Message)

	go func() {
		for i := range in {
			msg := new(Message)

			if i == "" {
				msg.Priv, _ = address.NewPrivateKey(nil)
			} else {
				var err error
				msg.Priv, err = address.ReadPrivateKey(i)
				if err != nil {
					log.Println(err)
					continue
				}
			}

			msg.Bip38 = address.BIP38Encrypt(msg.Priv, pass)
			out <- msg
		}
		close(out)
	}()

	return
}

func decrypter(pass string) (in chan string, out chan *Message) {

	in = make(chan string)
	out = make(chan *Message)

	go func() {
		for i := range in {
			var err error
			msg := new(Message)

			msg.Bip38, err = address.BIP38LoadString(i)
			if err != nil {
				log.Println(err)
				continue
			}

			msg.Priv, err = msg.Bip38.BIP38Decrypt(pass)
			if err != nil {
				log.Println(err)
				continue
			}

			out <- msg
		}
		close(out)
	}()

	return
}

func writerCSV(in chan *Message) (out chan int) {

	out = make(chan int)

	go func() {
		fmt.Println("Public Key,BIP38 Key")

		for i := range in {
			fmt.Printf("%s,%s\n", i.Priv.PublicKey, i.Bip38)
		}

		out <- 1
		close(out)
	}()

	return
}

func writerDetail(in chan *Message) (out chan int) {

	out = make(chan int)

	go func() {
		for i := range in {
			fmt.Println("---")
			fmt.Printf("Address:    %s\n", i.Priv.Address())
			fmt.Printf("PublicHex:  %x\n", i.Priv.PublicKey.Bytes())
			fmt.Printf("Private:    %s\n", i.Priv)
			fmt.Printf("PrivateHex: %x\n", i.Priv.Bytes())
			fmt.Printf("Bip38:      %s\n", i.Bip38)
			fmt.Printf("Bip38Hex:   %x\n", i.Bip38.Bytes())
			fmt.Println("...")
		}

		out <- 1
		close(out)
	}()

	return
}
