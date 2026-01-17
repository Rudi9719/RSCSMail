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
	"sync"
	"time"
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
	out, err := cmd.CombinedOutput()
	if err != nil {
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
	var realSender string

	for scanner.Scan() {
		line := scanner.Text()

		if parsingHeaders {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}

			if strings.Contains(strings.ToUpper(line), "MSG:FROM:") {
				parts := strings.SplitN(line, ":", 3)
				if len(parts) >= 3 {
					realSender = strings.TrimSpace(parts[2])
				}
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

				log.Printf("Skipping unknown header line: %s", line)
				continue
			}

			parsingHeaders = false
			if strings.HasPrefix(line, "[PUBVM") {
				break
			}
			if isGarbage(line) {
				continue
			}
			bodyLines = append(bodyLines, line)
		} else {
			if strings.HasPrefix(line, "[PUBVM") {
				break
			}
			if isGarbage(line) {
				continue
			}
			bodyLines = append(bodyLines, line)
		}
	}

	to := headers["to"]
	textFrom := headers["from"]
	subject := headers["subject"]

	if !strings.Contains(realSender, "@") {
		fields := strings.Fields(realSender)
		if len(fields) > 0 {
			realSender = fields[0]
		}
		realSender = fmt.Sprintf("%s@%s", realSender, config.Server.Domain)
	}

	finalFrom := realSender
	if textFrom != "" {
		cleanName := strings.Trim(textFrom, "\"")
		finalFrom = fmt.Sprintf("\"%s\" <%s>", cleanName, realSender)
	}

	if to == "" {
		log.Printf("Skipping %s: missing To in parsed content", path)
		return
	}

	body := strings.Join(bodyLines, "\r\n")

	msg := &bytes.Buffer{}
	fmt.Fprintf(msg, "From: %s\r\n", finalFrom)
	fmt.Fprintf(msg, "To: %s\r\n", to)
	if cc := headers["cc"]; cc != "" {
		fmt.Fprintf(msg, "Cc: %s\r\n", cc)
	}
	fmt.Fprintf(msg, "Subject: %s\r\n", subject)

	if headers["date"] == "" {
		fmt.Fprintf(msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	} else {
		fmt.Fprintf(msg, "Date: %s\r\n", headers["date"])
	}
	if headers["message-id"] == "" {
		msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), "rscs", config.Server.Domain)
		fmt.Fprintf(msg, "Message-ID: %s\r\n", msgID)
	} else {
		fmt.Fprintf(msg, "Message-ID: %s\r\n", headers["message-id"])
	}

	fmt.Fprintf(msg, "\r\n%s", body)

	signedMsg, err := signDKIM(msg.Bytes(), realSender)
	if err != nil {
		log.Printf("DKIM signing failed (sending unsigned): %v", err)
		signedMsg = msg.Bytes()
	}

	var sendErr error
	target := config.Spool.TargetSMTP

	var allRecipients []string

	seen := make(map[string]bool)
	addRecipients := func(s string) {
		for _, r := range strings.Split(s, ",") {
			r = strings.TrimSpace(r)
			if r != "" && !seen[r] {
				allRecipients = append(allRecipients, r)
				seen[r] = true
			}
		}
	}

	addRecipients(to)
	addRecipients(headers["cc"])
	addRecipients(headers["bcc"])

	if target == "" {
		log.Printf("Relaying mail from %s to %d recipients via Direct MX", realSender, len(allRecipients))
		for _, rcpt := range allRecipients {
			if err := sendDirectMX(realSender, rcpt, signedMsg); err != nil {
				log.Printf("Failed to send to %s via Direct MX: %v", rcpt, err)
				sendErr = err
			}
		}
	} else {
		log.Printf("Relaying mail from %s to %v via %s", realSender, allRecipients, target)
		var auth smtp.Auth
		if config.Spool.TargetUser != "" {
			host, _, _ := net.SplitHostPort(target)
			auth = smtp.PlainAuth("", config.Spool.TargetUser, config.Spool.TargetPass, host)
		}
		sendErr = sendMail(target, auth, realSender, allRecipients, signedMsg, true)
	}

	if sendErr != nil {
		log.Printf("Delivery failed permanently: %v. Generating bounce to %s via NJE", sendErr, realSender)

		bounceErr := sendBounce(realSender, to, sendErr.Error())
		if bounceErr != nil {
			log.Printf("Failed to send bounce notification: %v", bounceErr)
		}
	}

	ackCmd := exec.Command("sudo", "-u", "smtp", receiveCmd, "-o", "/dev/null", path)
	if out, err := ackCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to ack/delete spool file %s: %v. Out: %s", path, err, string(out))
		os.Remove(path)
	} else {
		log.Printf("Successfully processed (and cleaned up) %s", path)
	}
}

func sendBounce(recipient, failedRcpt, reason string) error {
	bounceSender := fmt.Sprintf("MAILER-DAEMON@%s", config.Server.Domain)
	subject := fmt.Sprintf("Undeliverable: Mail to %s", failedRcpt)

	timestamp := time.Now().Format(time.RFC1123Z)

	msg := &bytes.Buffer{}
	fmt.Fprintf(msg, "From: %s\r\n", bounceSender)
	fmt.Fprintf(msg, "To: %s\r\n", recipient)
	fmt.Fprintf(msg, "Subject: %s\r\n", subject)
	fmt.Fprintf(msg, "Date: %s\r\n", timestamp)
	fmt.Fprintf(msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(msg, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(msg, "\r\n")
	fmt.Fprintf(msg, "This is the RSCS/SMTP Gateway at %s.\r\n\r\n", config.Server.Domain)
	fmt.Fprintf(msg, "I wasn't able to deliver your message to the following addresses.\r\n")
	fmt.Fprintf(msg, "This is a permanent error.\r\n\r\n")
	fmt.Fprintf(msg, "<%s>:\r\n", failedRcpt)
	fmt.Fprintf(msg, "%s\r\n", reason)

	tmpFile, err := os.CreateTemp("", "bounce-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file for bounce: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(msg.Bytes()); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write bounce content: %v", err)
	}
	tmpFile.Close()

	user := recipient
	node := ""
	if idx := strings.LastIndex(recipient, "@"); idx != -1 {
		user = recipient[:idx]
		node = recipient[idx+1:]
	}

	return sendOverNJE(user, node, tmpFile.Name(), "MAIL", "TXT", "Undeliverable Mail")
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
		} else {
			return fmt.Errorf("authentication required but server did not advertise AUTH extension")
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
	const smtpPort = "25"

	for _, mx := range mxs {
		target := fmt.Sprintf("%s:%s", mx.Host, smtpPort)
		log.Printf("Attempting delivery to %s...", target)
		if err := sendMail(target, nil, from, []string{to}, msg, true); err == nil {
			log.Printf("Delivery successful to %s", target)
			return nil
		} else {
			log.Printf("Failed to send to %s: %v", target, err)
		}
	}

	return fmt.Errorf("all MX records failed for %s", domain)
}

func isGarbage(line string) bool {
	nonPrintable := 0
	for _, r := range line {
		if r < 32 && r != '\t' {
			nonPrintable++
		} else if r > 126 {
			nonPrintable++
		}
	}

	if len(line) > 0 && float64(nonPrintable)/float64(len(line)) > 0.2 {
		return true
	}
	if nonPrintable > 5 {
		return true
	}

	if strings.Contains(line, "DKIM Testing") && nonPrintable > 0 {
		return true
	}

	return false
}
