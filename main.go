package main

import (
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"net/url"

	dgoogauth "github.com/dgryski/dgoogauth"
	qr "rsc.io/qr"
)

const (
	qrFilename = "./tmp/qr.png"
)

func main() {
	// Example secret from here:
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	secret := []byte{'n', '.', 'v', 't', 'o', 'r', 'u', 's', 'h', 'i', 'n', 0xDE, 0xAD, 0xBE, 0xEF}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	account := "n.vtorushin@inbox.ru"
	issuer := "SmartWorld.team"

	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secretBase32)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	fmt.Printf("URL is %s\n", URL.String())

	code, err := qr.Encode(URL.String(), qr.Q)
	if err != nil {
		panic(err)
	}
	b := code.PNG()
	err = ioutil.WriteFile(qrFilename, b, 0600)
	if err != nil {
		panic(err)
	}

	fmt.Printf("QR code is in %s. Please scan it into Google Authenticator app.\n", qrFilename)

	// The OTPConfig gets modified by otpc.Authenticate() to prevent passcode replay, etc.,
	// so allocate it once and reuse it for multiple calls.
	otpc := &dgoogauth.OTPConfig{
		Secret:      secretBase32,
		WindowSize:  3,
		HotpCounter: 0,
		// UTC:         true,
	}

	for {
		var token string
		fmt.Printf("Please enter the token value (or q or quit to quit): ")
		fmt.Scanln(&token)

		if token == "q" || token == "quit" {
			break
		}

		val, err := otpc.Authenticate(token)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if !val {
			fmt.Println("Sorry, Not Authenticated")
			continue
		}

		fmt.Println("Authenticated!")
	}
	return
}
