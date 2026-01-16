package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mileusna/spf"
)

func ensureDKIMKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	log.Printf("DKIM key not found at %s. Generating 2048-bit RSA key...", path)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate DKIM key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Printf("Warning: failed to marshal public key for display: %v", err)
		return nil
	}

	pubBase64 := base64.StdEncoding.EncodeToString(pubBytes)
	log.Printf("********************************************************************************")
	log.Printf("* DKIM Key Generated: %s", path)
	log.Printf("* DNS TXT Record (Selector: default):")
	log.Printf("* v=DKIM1; k=rsa; p=%s", pubBase64)
	log.Printf("********************************************************************************")

	return nil
}

func checkEmailSecurity(ip string, hello string, from string, msg []byte) (bool, string) {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	netIP := net.ParseIP(ip)
	if netIP == nil || netIP.IsLoopback() || netIP.IsPrivate() {
		return true, ""
	}

	domain := "unknown"
	parts := strings.Split(from, "@")
	if len(parts) == 2 {
		domain = parts[1]
	}

	spfRes := spf.CheckHost(netIP, domain, from, hello)
	spfPass := (spfRes == spf.Pass)

	reader := bytes.NewReader(msg)
	verifications, err := dkim.Verify(reader)
	dkimPass := false
	if err == nil {
		for _, v := range verifications {
			if v.Err == nil {
				dkimPass = true
				break
			}
		}
	}

	dmarcRecord, err := dmarc.Lookup(domain)
	if err != nil {
		if spfRes == spf.Fail {
			return false, fmt.Sprintf("SPF Fail for %s", domain)
		}
		return true, ""
	}
	dmarcPassed := false
	if spfPass {
		dmarcPassed = true
	}
	if dkimPass {
		dmarcPassed = true
	}

	if !dmarcPassed {
		if dmarcRecord.Policy == dmarc.PolicyReject || dmarcRecord.Policy == dmarc.PolicyQuarantine {
			return false, fmt.Sprintf("DMARC %s (SPF=%v, DKIM=%v)", dmarcRecord.Policy, spfRes, dkimPass)
		}
	}

	return true, ""
}

func signDKIM(msg []byte, from string) ([]byte, error) {
	domain := "unknown"
	if parts := strings.Split(from, "@"); len(parts) == 2 {
		domain = parts[1]
	}

	dmConfig, ok := config.Routing.DomainMap[domain]
	if !ok || dmConfig.DkimKeyPath == "" {
		dmConfig.DkimKeyPath = "dkim_private.pem"
		dmConfig.DkimSelector = "default"
	}

	keyData, err := os.ReadFile(dmConfig.DkimKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read DKIM key from %s: %v", dmConfig.DkimKeyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	selector := dmConfig.DkimSelector
	if selector == "" {
		selector = "default"
	}

	options := &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   key,
	}

	var signedBuf bytes.Buffer
	if err := dkim.Sign(&signedBuf, bytes.NewReader(msg), options); err != nil {
		return nil, err
	}

	return signedBuf.Bytes(), nil
}
