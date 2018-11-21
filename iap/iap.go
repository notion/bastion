package iap

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// IAP is an IAP verification tool for Gin
type IAP struct {
	Keys          map[string]string
	KeyLoadTime   time.Time
	Audience      string
	Issuer        string
	HostedDomains []string
}

// NewIAPVerifier Creates an IAP verifier with the given parameters
func NewIAPVerifier(audience string, issuer string, hosteddomains []string) *IAP {
	return &IAP{
		Keys:          make(map[string]string),
		Audience:      audience,
		Issuer:        issuer,
		HostedDomains: hosteddomains,
	}
}

// Verify verifies that a request abides by the IAP settings defined in the IAP type
func (i *IAP) Verify(assertion string) (bool, jwt.MapClaims, error) {
	if int(time.Now().Sub(i.KeyLoadTime).Seconds()) > 60 {
		i.KeyLoadTime = time.Now()

		resp, err := http.Get("https://www.gstatic.com/iap/verify/public_key")
		if err != nil {
			return false, nil, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, nil, err
		}

		err = json.Unmarshal(body, &i.Keys)
		if err != nil {
			return false, nil, err
		}
	}

	if assertion != "" {
		token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			key, err := jwt.ParseECPublicKeyFromPEM([]byte(i.Keys[token.Header["kid"].(string)]))
			if err != nil {
				return nil, err
			}

			return key, nil
		})
		if err != nil {
			return false, nil, err
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims.VerifyAudience(i.Audience, true) && claims.VerifyIssuer(i.Issuer, true) {
				if hd, ok := claims["hd"].(string); ok {
					for _, v := range i.HostedDomains {
						if v == hd {
							return true, claims, nil
						}
					}
				}
			}
		}
	} else {
		return false, nil, fmt.Errorf("no jwt assertion present")
	}

	return false, nil, fmt.Errorf("jwt verification invalid")
}
