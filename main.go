package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/abennett/cryptlog/cryptloggers"
)

const cryptLogPassEnv = "CRYPTLOG_PASS"

func main() {
	password, ok := os.LookupEnv(cryptLogPassEnv)
	if !ok {
		log.Fatalf("missing %s envvar", cryptLogPassEnv)
	}
	if len(os.Args) != 2 {
		log.Fatal("wrong number of arguments")
	}
	fcl, err := cryptloggers.OpenFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer fcl.Close()
	cl, err := New(password)
	if err != nil {
		log.Fatal(err)
	}
	stat, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if stat.Mode()&os.ModeCharDevice == 0 {
		input, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		err = cl.Append(fcl, input)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	b, err := cl.Decrypt(fcl)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}
