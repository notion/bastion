package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/notion/trove_ssh_bastion/config"
)

func createPrivateKey(env *config.Env) []byte {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		env.Red.Fatal(err)
	}

	env.Blue.Println("Generated RSA Keypair")

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		},
	)

	bytes := []byte(pemdata)

	env.Config.PrivateKey = bytes

	return bytes
}