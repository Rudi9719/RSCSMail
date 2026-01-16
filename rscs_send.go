package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sync"
)

var (
	processingFiles sync.Map
)

// StartSpoolMonitor polls the configured directory for new files.
func StartSpoolMonitor() {
	if config.Spool.Directory == "" {
		log.Println("Spool monitor disabled (no directory configured)")
		return
	}

	interval, err := time.ParseDuration(config.Spool.Interval)
	if err != nil {
		interval = 5 * time.Second
	}

	log.Printf("Starting spool monitor on %s (interval: %s)", config.Spool.Directory, interval)

	ticker := time.NewTicker(interval)
	for range ticker.C {
		scanSpool()
	}
}

func scanSpool() {
	files, err := os.ReadDir(config.Spool.Directory)
	if err != nil {
		log.Printf("Error reading spool directory: %v", err)
		return
	}

	for _, file := range files {
		if !file.IsDir() && !strings.HasPrefix(file.Name(), ".") {
			fullPath := filepath.Join(config.Spool.Directory, file.Name())

			if _, loaded := processingFiles.LoadOrStore(fullPath, true); loaded {
				continue
			}

			go func(path string) {
				defer processingFiles.Delete(path)
				processSpoolFile(path)
			}(fullPath)
		}
	}
}

func processSpoolFile(path string) {
	receiveCmd := config.NJE.ReceivePath
	if receiveCmd == "" {
		receiveCmd = "receive"
	}

	tempFile := filepath.Join("/tmp", filepath.Base(path)+".txt")

	defer os.Remove(tempFile)

	cmd := exec.Command("sudo", "-u", "smtp", receiveCmd, "-n", "-o", tempFile, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to execute receive for %s: %v. Output: %s", path, err, string(out))
		return
	}

	content, err := os.ReadFile(tempFile)
	if err != nil {
		log.Printf("Failed to read converted temp file %s: %v", tempFile, err)
		return
	}
	headers := make(map[string]string)
	bodyLines := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	parsingHeaders := true

	for scanner.Scan() {
		line := scanner.Text()

		if parsingHeaders {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}

			if strings.Contains(strings.ToUpper(line), "MSG:FROM:") {
				continue
			}

			if idx := strings.Index(line, ":"); idx > 0 {
				rawKey := line[:idx]
				key := strings.ToLower(strings.TrimFunc(rawKey, func(r rune) bool {
					return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
				}))

				val := strings.TrimSpace(line[idx+1:])

				switch key {
				case "to", "toa":
					upperVal := strings.ToUpper(val)
					if strings.Contains(upperVal, "SMTP") && strings.Contains(upperVal, "--PUBNET") {
						continue
					}
					headers["to"] = val
				case "from", "frm":
					headers["from"] = val
				case "cc":
					headers["cc"] = val
				case "bcc":
					headers["bcc"] = val
				case "subject":
					headers["subject"] = val
				}

				if key == "to" || key == "toa" || key == "from" || key == "frm" || key == "cc" || key == "bcc" || key == "subject" {
					continue
				}
			}

			parsingHeaders = false
			if strings.HasPrefix(line, "[PUBVM") {
				break
			}
			bodyLines = append(bodyLines, line)
		} else {
			if strings.HasPrefix(line, "[PUBVM") {
				break
			}
			bodyLines = append(bodyLines, line)
		}
	}

	to := headers["to"]
	from := headers["from"]
	subject := headers["subject"]

	if to == "" || from == "" {
		log.Printf("Skipping %s: missing To/From in parsed content", path)
		return
	}

	body := strings.Join(bodyLines, "\r\n")

	msg := &bytes.Buffer{}
	fmt.Fprintf(msg, "From: %s\r\n", from)
	fmt.Fprintf(msg, "To: %s\r\n", to)
	if cc := headers["cc"]; cc != "" {
		fmt.Fprintf(msg, "Cc: %s\r\n", cc)
	}
	fmt.Fprintf(msg, "Subject: %s\r\n", subject)
	fmt.Fprintf(msg, "\r\n%s", body)

	signedMsg, err := signDKIM(msg.Bytes(), from)
	if err != nil {
		log.Printf("DKIM signing failed (sending unsigned): %v", err)
		signedMsg = msg.Bytes()
	}

	target := config.Spool.TargetSMTP
	if target == "" {
		log.Printf("Relaying mail from %s to %s via Direct MX", from, to)
		if err := sendDirectMX(from, to, signedMsg); err != nil {
			log.Printf("Failed to send email from spool %s: %v", path, err)
			return
		}
	} else {
		log.Printf("Relaying mail from %s to %s via %s", from, to, target)

		var auth smtp.Auth
		if config.Spool.TargetUser != "" {
			host, _, _ := net.SplitHostPort(target)
			auth = smtp.PlainAuth("", config.Spool.TargetUser, config.Spool.TargetPass, host)
		}

		if err := sendMail(target, auth, from, []string{to}, signedMsg, true); err != nil {
			log.Printf("Failed to send email from spool %s: %v", path, err)
			return
		}
	}

	ackCmd := exec.Command("sudo", "-u", "smtp", receiveCmd, path)
	if out, err := ackCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to ack/delete spool file %s: %v. Out: %s", path, err, string(out))
		os.Remove(path)
	} else {
		log.Printf("Successfully processed and acked %s", path)
	}
}

func sendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte, skipVerify bool) error {
	host, port, _ := net.SplitHostPort(addr)

	var c *smtp.Client
	var err error

	if port == "465" {
		log.Printf("Connecting via Implicit TLS (SMTPS) to %s", addr)
		tlsConfig := &tls.Config{InsecureSkipVerify: skipVerify, ServerName: host}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", addr, tlsConfig)
		if err != nil {
			return err
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return err
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			return err
		}

		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return err
		}
	}
	defer c.Close()
	heloName := config.Server.Domain
	if heloName == "" {
		heloName = "localhost"
	}
	if err := c.Hello(heloName); err != nil {
		return err
	}

	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{InsecureSkipVerify: skipVerify, ServerName: host}
			if err = c.StartTLS(tlsConfig); err != nil {
				log.Printf("Warning: Failed to Upgrade to TLS: %v", err)
				return err
			}
		}
	}

	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				return err
			}
		}
	}

	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

func sendDirectMX(from, to string, msg []byte) error {
	parts := strings.Split(to, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid to address: %s", to)
	}
	domain := parts[1]

	mxs, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("mx lookup failed for %s: %v", domain, err)
	}

	if len(mxs) == 0 {
		return fmt.Errorf("no MX records found for %s", domain)
	}

	for _, mx := range mxs {
		ports := []string{"587", "465", "25"}
		for _, port := range ports {
			target := fmt.Sprintf("%s:%s", mx.Host, port)
			log.Printf("Attempting delivery to %s...", target)

			if err := sendMail(target, nil, from, []string{to}, msg, true); err == nil {
				return nil
			} else {
				log.Printf("Failed to send to %s: %v", target, err)
			}
		}
	}

	return fmt.Errorf("all MX records failed for %s", domain)
}
