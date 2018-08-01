package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/hibooboo2/crypto/bleh"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalln(`
            Usage:
            %[1]s encrypt key filename : encrypts the file at filename (stores backup of original at .bak.ec)
            %[1]s decrypt key filename : decrypts the file at filename (stores backup of original at .bak.dc)
`)
	}
	k := bleh.HashArr([]byte(os.Args[2]))

	data, err := ioutil.ReadFile(os.Args[3])
	if err != nil && err != io.EOF {
		log.Fatalln(err)
	}
	var result []byte
	switch os.Args[1] {
	case "encrypt", "e":
		result, err = k.Encrypt(data)
	case "decrypt", "d":
		result, err = k.Decrypt(data)
	}
	if err != nil {
		log.Fatalln(err)
	}
	ioutil.WriteFile(os.Args[3]+"."+os.Args[1][:1]+"c", data, 0644)
	ioutil.WriteFile(os.Args[3], result, 0644)
}
