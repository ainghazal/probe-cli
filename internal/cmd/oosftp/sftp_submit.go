package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/apex/log"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const sftpSubmitHelp = "Submits an OONI report via SFTP"

var (
	sftpDefaultUser = "ooni"
)

// TODO this needs to be inserted from the one used by the server (only the field #1).
// TODO we might want to use go generate for that...
var hostPublicKey = `AAAAC3NzaC1lZDI1NTE5AAAAIAY3dGnI8l9cMP1LwMnhXFNJll5YZfOLEUoqCvLyodBi`

// Submits a report to the remote SFTP endpoint.
func mainSubmit(args []string) {
	if len(args) != 3 {
		ErrPrintf("Wrong arguments: %s report.jsonl server:port\n", args[0])
		return
	}

	reportPath := args[1]
	remoteAddr := args[2]

	log.Infof("report: %s", reportPath)
	log.Infof("remote: %s", remoteAddr)

	key, err := os.ReadFile("client")
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	// decode public key for host (it's hard-coded on this client).
	rawKey, _ := base64.StdEncoding.DecodeString(hostPublicKey)
	hostKey, err := ssh.ParsePublicKey(rawKey)
	if err != nil {
		panic(err)
	}

	config := &ssh.ClientConfig{
		User: sftpDefaultUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	// connect
	conn, err := ssh.Dial("tcp", remoteAddr, config)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	// create new SFTP client
	client, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer client.Close()

	// open source file (report)
	srcFile, err := os.Open(reportPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	// create destination file
	dstFile, err := client.Create(fmt.Sprintf("./report-%d.jsonl", rand.Intn(99999)))
	if err != nil {
		log.Fatal(err.Error())
	}
	defer dstFile.Close()

	// copy source file to destination file
	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("%d bytes copied\n", bytes)

	// TODO we should try and loop for any report-id that the server might have written back...
}
