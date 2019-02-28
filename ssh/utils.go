package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/notion/bastion/config"
	"golang.org/x/crypto/ssh"
)

var sshPermissions = map[string]string{
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
}

// CASigner is the main CASigner object
type CASigner struct {
	CA          ssh.Signer
	Validity    time.Duration
	Principals  []string
	Permissions []string
}

// Sign creates a certificate that has been signed by the CASigner
func (s *CASigner) Sign(env *config.Env, user string, pubKey ssh.PublicKey) (*ssh.Certificate, []byte, error) {
	var privateKey []byte
	if pubKey == nil {
		privateKey = createPrivateKey(env, false, "")

		pk, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			env.Red.Println("Unable to parse created private key:", err)
			return nil, privateKey, err
		}

		pubKey = pk.PublicKey()
	}

	expires := time.Now().UTC().Add(s.Validity)

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           fmt.Sprintf("%s_%d", user, time.Now().UTC().Unix()),
		ValidAfter:      uint64(time.Now().UTC().Unix()),
		ValidBefore:     uint64(expires.Unix()),
		ValidPrincipals: []string{user},
	}

	cert.ValidPrincipals = append(cert.ValidPrincipals, s.Principals...)

	cert.CriticalOptions = make(map[string]string)
	cert.Extensions = make(map[string]string)

	for _, perm := range s.Permissions {
		if strings.Contains(perm, "=") {
			opt := strings.Split(perm, "=")
			cert.CriticalOptions[strings.TrimSpace(opt[0])] = strings.TrimSpace(opt[1])
		} else {
			cert.Extensions[perm] = ""
		}
	}

	if len(cert.Extensions) == 0 {
		cert.Extensions = sshPermissions
	}

	if err := cert.SignCert(rand.Reader, s.CA); err != nil {
		return nil, privateKey, err
	}

	return cert, privateKey, nil
}

// NewCASigner creates a CASigner from different certificate settings
func NewCASigner(sshsigner ssh.Signer, expireIn time.Duration, principals []string, permissions []string) *CASigner {
	signer := &CASigner{
		CA:          sshsigner,
		Validity:    expireIn,
		Principals:  principals,
		Permissions: permissions,
	}

	return signer
}

func createPrivateKey(env *config.Env, addToEnv bool, passphrase string) []byte {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		env.Red.Fatal(err)
	}

	env.Blue.Println("Generated RSA Keypair")

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}

	var pemData []byte

	if passphrase != "" {
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			env.Red.Fatal("Unable to encrypt Private Key:", err)
		}

		pemData = pem.EncodeToMemory(encBlock)
	} else {
		pemData = pem.EncodeToMemory(pemBlock)
	}

	if addToEnv {
		env.Config.PrivateKey = pemData
	}

	return pemData
}

// ParsePrivateKey pareses the PrivateKey into a ssh.Signer and let's it be used by CASigner
func ParsePrivateKey(pk []byte, passphrase string, env *config.Env) ssh.Signer {
	var signer ssh.Signer
	var err error
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pk, []byte(passphrase))
		if err != nil {
			env.Red.Fatal("Unable to parse private key:", err)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pk)
		if err != nil {
			env.Red.Fatal("Unable to parse private key:", err)
		}
	}

	return signer
}

func initializeCerts(env *config.Env, force bool) {
	for _, v := range []string{"PrivateKey", "ServerPrivateKey", "UserPrivateKey"} {
		var pkBytes []byte

		r := reflect.ValueOf(env.Config)
		f := reflect.Indirect(r).FieldByName(v)

		pkBytes = f.Bytes()

		if len(pkBytes) == 0 || force {
			pkBytes = createPrivateKey(env, false, env.PKPassphrase)
		}

		signer := ParsePrivateKey(pkBytes, env.PKPassphrase, env)
		shaHash := sha256.Sum256(signer.PublicKey().Marshal())

		env.Yellow.Println(fmt.Sprintf("Private key information for %s: \nPublic Key: %sSHA256: %s", v, string(ssh.MarshalAuthorizedKey(signer.PublicKey())), base64.StdEncoding.EncodeToString(shaHash[:])))

		if len(f.Bytes()) > 0 && !force {
			continue
		}

		switch v {
		case "PrivateKey":
			env.Config.PrivateKey = pkBytes
			break
		case "ServerPrivateKey":
			env.Config.ServerPrivateKey = pkBytes
			break
		case "UserPrivateKey":
			env.Config.UserPrivateKey = pkBytes
			break
		}
	}

	return
}

// RandStringBytesMaskImprSrc creates a random string of n length
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go/31832326
func RandStringBytesMaskImprSrc(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	var src = mathrand.NewSource(time.Now().UnixNano())

	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// GetRegexMatches will return a slice of all of the matching regexes for a user
func GetRegexMatches(user *config.User) []string {
	matchers := []string{user.AuthorizedHosts}

	for _, v := range user.AuthRules {
		matchers = append(matchers, v.AuthorizedHosts)
	}

	return matchers
}

// WaitTimeout waits for a waitgroup
func WaitTimeout(group *sync.WaitGroup, timeout time.Duration) bool {
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		group.Wait()
	}()
	select {
	case <-stop:
		return false
	case <-time.After(timeout):
		return true
	}
}
