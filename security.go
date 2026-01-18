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
	freshKey := false
	if _, err := os.Stat(path); err != nil {
		log.Printf("DKIM key not found at %s. Generating 2048-bit RSA key...", path)
		freshKey = true

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
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read DKIM key: %v", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode DKIM key pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse DKIM key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Printf("Warning: failed to marshal public key for display: %v", err)
		return nil
	}

	pubBase64 := base64.StdEncoding.EncodeToString(pubBytes)

	selector := config.Routing.DkimSelector
	if selector == "" {
		selector = "default"
	}
	domain := config.Server.Domain
	dnsName := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	dnsMatch := false
	if !freshKey {
		txtRecords, err := net.LookupTXT(dnsName)
		if err == nil {
			for _, record := range txtRecords {
				cleanRecord := strings.ReplaceAll(record, " ", "")
				if strings.Contains(cleanRecord, "p="+pubBase64) {
					dnsMatch = true
					break
				}
			}
		} else {
			log.Printf("DNS Lookup failed for %s: %v", dnsName, err)
		}
	}

	if freshKey || !dnsMatch {
		if !freshKey && !dnsMatch {
			log.Printf("WARNING: DKIM DNS record mismatch or missing for %s", dnsName)
		}

		log.Printf("********************************************************************************")
		log.Printf("* DKIM Key Loaded: %s", path)
		log.Printf("* DNS TXT Record (Selector: %s):", selector)
		log.Printf("v=DKIM1; k=rsa; p=%s", pubBase64)
		log.Printf("********************************************************************************")
	} else {
		log.Printf("DKIM Key verified in DNS for %s (selector: %s)", domain, selector)
	}

	return nil
}

func ensureSPFRecord() {
	ip, err := getOutboundIP()
	if err != nil {
		log.Printf("Warning: Could not determine outbound IP for SPF check: %v", err)
		return
	}

	sender := fmt.Sprintf("%s@%s", config.Routing.ErrorRecipient, config.Server.Domain)
	res := spf.CheckHost(ip, config.Server.Domain, sender, config.Server.Domain)

	if res == spf.Pass {
		log.Printf("SPF record verified in DNS for %s (allows %s)", config.Server.Domain, ip)
	} else {
		log.Printf("********************************************************************************")
		log.Printf("* SPF Record Missing or Invalid for %s", config.Server.Domain)
		log.Printf("* Current IP %s is NOT allowed (Result: %s)", ip, res)
		log.Printf("* Suggested Record:")
		log.Printf("v=spf1 ip4:%s -all", ip)
		log.Printf("********************************************************************************")
	}
}

func ensureDMARCRecord() {
	dmarcName := fmt.Sprintf("_dmarc.%s", config.Server.Domain)
	expectedRUA := fmt.Sprintf("mailto:%s", config.Routing.ErrorRecipient)

	txtRecords, err := net.LookupTXT(dmarcName)
	dmarcMatch := false

	if err == nil {
		for _, record := range txtRecords {
			cleanRecord := strings.ReplaceAll(record, " ", "")
			if strings.Contains(cleanRecord, "v=DMARC1") && strings.Contains(cleanRecord, "rua="+expectedRUA) {
				dmarcMatch = true
				break
			}
		}
	} else {
		log.Printf("DNS Lookup failed for %s: %v", dmarcName, err)
	}

	if !dmarcMatch {
		log.Printf("********************************************************************************")
		log.Printf("* DMARC Record Missing or Invalid for %s", config.Server.Domain)
		log.Printf("* Suggested Record:")
		log.Printf("v=DMARC1; p=quarantine; rua=%s", expectedRUA)
		log.Printf("********************************************************************************")
	} else {
		log.Printf("DMARC record verified in DNS for %s", config.Server.Domain)
	}
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

	dkimKeyPath := config.Routing.DkimKeyPath
	if dkimKeyPath == "" {
		dkimKeyPath = "dkim_private.pem"
	}

	keyData, err := os.ReadFile(dkimKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read DKIM key from %s: %v", dkimKeyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	selector := config.Routing.DkimSelector
	if selector == "" {
		selector = "default"
	}

	options := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys: []string{
			"From", "To", "Cc", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type",
		},
	}

	var signedBuf bytes.Buffer
	if err := dkim.Sign(&signedBuf, bytes.NewReader(msg), options); err != nil {
		return nil, err
	}

	return signedBuf.Bytes(), nil
}

func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}
