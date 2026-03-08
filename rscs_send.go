package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// StartSpoolMonitor polls the configured directory for new files.
func StartSpoolMonitor() {
	if config.Spool.Directory == "" {
		log.Println("Spool monitor disabled (no directory configured)")
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(config.Spool.Directory)
	if err != nil {
		log.Printf("Failed to watch spool directory %s: %v", config.Spool.Directory, err)
		return
	}

	log.Printf("Starting spool monitor on %s (using fsnotify)", config.Spool.Directory)

	// Process any existing files on startup
	scanSpool()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// React to new or modified files
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				scanSpool()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Spool watcher error: %v", err)
		}
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

func parseRSCSHeaders(r io.Reader) (map[string]string, error) {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if isGarbage(line) {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
		if line == "END:" {
			break
		}
	}
	return headers, scanner.Err()
}

func resolveNode(domain string) string {
	if idx := strings.LastIndex(domain, "@"); idx != -1 {
		domain = domain[idx+1:]
	}
	for _, pair := range config.Routing.Domains {
		if strings.EqualFold(pair.INetDomain, domain) {
			return pair.RSCSNode
		}
	}
	return ""
}

func resolveSender(user, node string) string {
	for _, pair := range config.Routing.Domains {
		if strings.EqualFold(pair.RSCSNode, node) {
			return fmt.Sprintf("%s@%s", strings.ToLower(user), pair.INetDomain)
		}
	}
	return fmt.Sprintf("%s@%s", strings.ToLower(user), config.Routing.Domains[0].INetDomain)
}

func processSpoolFile(path string) {
	receiveCmd := config.NJE.ReceivePath
	if receiveCmd == "" {
		receiveCmd = "receive"
	}

	var rscsSender string
	f, err := os.Open(path)
	if err == nil {
		rscsHeaders, _ := parseRSCSHeaders(f)
		f.Close()
		if frm, ok := rscsHeaders["FRM"]; ok {
			parts := strings.Split(frm, "@")
			if len(parts) == 2 {
				rscsSender = resolveSender(parts[0], parts[1])
				log.Printf("Parsed RSCS Sender: %s -> %s", frm, rscsSender)
			}
		}
	} else {
		log.Printf("Warning: failed to open spool file for header parsing: %v", err)
	}

	tempFile := filepath.Join("/tmp", filepath.Base(path)+".txt")

	defer os.Remove(tempFile)

	cmd := exec.Command("sudo", "-u", config.NJE.RunAsUser, receiveCmd, "-n", "-o", tempFile, path)
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
	realSender, finalFrom, to, subject, headers, body := parseSpoolData(content, string(out), rscsSender)

	if to == "" {
		log.Printf("Skipping %s: missing To in parsed content", path)
		return
	}

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
		msgID := fmt.Sprintf("<%d.%s>", time.Now().UnixNano(), realSender)
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
		for _, part := range strings.Split(s, ",") {
			for _, r := range strings.Fields(part) {
				r = strings.TrimSpace(r)
				if r != "" && strings.Contains(r, "@") && !seen[r] {
					allRecipients = append(allRecipients, r)
					seen[r] = true
				}
			}
		}
	}

	addRecipients(to)
	addRecipients(headers["cc"])
	addRecipients(headers["bcc"])

	if strings.HasPrefix(strings.ToLower(realSender), "guest") {
		log.Printf("Guests can not send email: Generating bounce to %s via NJE", realSender)

		bounceErr := sendBounce(realSender, to, "Guests can not send email")
		if bounceErr != nil {
			log.Printf("Failed to send bounce notification: %v", bounceErr)
		}
		return
	}

	if target == "" {
		var wg sync.WaitGroup
		var errMu sync.Mutex
		var failedRecipients []string
		domainRecipients := make(map[string][]string)

		log.Printf("Relaying mail from %s to %d recipients via Direct MX", realSender, len(allRecipients))
		for _, rcpt := range allRecipients {
			if idx := strings.LastIndex(rcpt, "@"); idx != -1 {
				domain := strings.ToLower(rcpt[idx+1:])
				domainRecipients[domain] = append(domainRecipients[domain], rcpt)
			}
		}

		for domain, rcpts := range domainRecipients {
			wg.Add(1)
			go func(domain string, rcpts []string) {
				defer wg.Done()
				for _, rcpt := range rcpts {
					if err := sendDirectMX(realSender, rcpt, signedMsg); err != nil {
						log.Printf("Failed to send to %s via Direct MX: %v", rcpt, err)
						errMu.Lock()
						failedRecipients = append(failedRecipients, rcpt)
						sendErr = err
						errMu.Unlock()
					}
				}
			}(domain, rcpts)
		}
		wg.Wait()

		if len(failedRecipients) > 0 {
			log.Printf("Failed to deliver to %d recipients: %v", len(failedRecipients), failedRecipients)
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

	if err := os.Remove(path); err != nil {
		log.Printf("Warning: failed to remove spool file %s: %v", path, err)
	} else {
		log.Printf("Removed processed spool file: %s", path)
	}
}

func sendBounce(recipient, failedRcpt, reason string) error {
	domain := resolveNode(recipient)
	bounceSender := fmt.Sprintf("%s@%s", config.NJE.RunAsUser, domain)
	subject := fmt.Sprintf("Undeliverable: Mail to %s", failedRcpt)

	bodyBuf := &bytes.Buffer{}
	fmt.Fprintf(bodyBuf, "This is RSCS Mail Gateway for %s.\n\n", domain)
	fmt.Fprintf(bodyBuf, "Your message could not be delivered to the following addresses.\n")
	fmt.Fprintf(bodyBuf, "This is a permanent error.\n\n")
	fmt.Fprintf(bodyBuf, "<%s>:\n", failedRcpt)
	fmt.Fprintf(bodyBuf, "%s\n", reason)

	ebcdicBuf, err := generateEbcdicNote(bounceSender, []string{recipient}, subject, bounceSender, bodyBuf, time.Now())
	if err != nil {
		return fmt.Errorf("failed to generate EBCDIC bounce: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "bounce-*.bin")
	if err != nil {
		return fmt.Errorf("failed to create temp file for bounce: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(ebcdicBuf.Bytes()); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write bounce content: %v", err)
	}
	tmpFile.Close()

	user := recipient
	node := ""
	if idx := strings.LastIndex(recipient, "@"); idx != -1 {
		user = recipient[:idx]
		domain := recipient[idx+1:]

		if resolvedNode := resolveNode(domain); resolvedNode != "" {
			node = resolvedNode
		} else {
			if !strings.Contains(domain, ".") && len(domain) <= 8 {
				node = strings.ToUpper(domain)
			} else {
				log.Printf("Warning: could not resolve NJE node for domain %s", domain)
				node = "UNKNOWN"
			}
		}
	}

	return sendOverNJE(user, node, tmpFile.Name(), "MAIL", "BOUNCE", subject)
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
	heloName := config.Server.EhloIdentity
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

	return false
}

func normalizeAddresses(s string) string {
	var addrs []string
	for _, part := range strings.Split(s, ",") {
		for _, addr := range strings.Fields(part) {
			addr = strings.TrimSpace(addr)
			if addr != "" && strings.Contains(addr, "@") {
				addrs = append(addrs, addr)
			}
		}
	}
	return strings.Join(addrs, ", ")
}

func parseSpoolData(content []byte, receiveOutput string, rscsSender string) (envelopeSender, headerFrom, to, subject string, headers map[string]string, body string) {
	headers = make(map[string]string)
	var bodyBuilder strings.Builder
	bodyBuilder.Grow(len(content))

	rscsNodePrefix := fmt.Sprintf("[%s", strings.ToUpper(config.Routing.RSCSNode))
	realSender := determineInitialSender(receiveOutput, rscsSender)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	firstBodyLine := true

	for scanner.Scan() {
		line := scanner.Text()

		if isGarbage(line) {
			continue
		}

		if strings.HasPrefix(line, rscsNodePrefix) {
			break
		}

		if strings.Contains(line, "MSG:FROM") && strings.Contains(line, strings.ToUpper(config.Routing.NJESender)) {
			continue
		}

		if parseHeaderLine(line, headers) {
			continue
		}

		if !firstBodyLine {
			bodyBuilder.WriteString("\r\n")
		}
		bodyBuilder.WriteString(line)
		firstBodyLine = false
	}
	to = headers["to"]
	subject = headers["subject"]
	headerFrom = finalizeFromHeader(headers["from"], realSender)
	return realSender, headerFrom, to, subject, headers, bodyBuilder.String()
}

func determineInitialSender(receiveOutput, rscsSender string) string {
	if rscsSender != "" {
		return rscsSender
	}
	if receiveOutput != "" {
		words := strings.Fields(receiveOutput)
		if len(words) >= 6 &&
			strings.EqualFold(words[2], "from") &&
			strings.EqualFold(words[4], "at") {

			rUser := words[3]
			rNode := words[5]
			return resolveSender(rUser, rNode)
		}
	}

	return ""
}

func finalizeFromHeader(headerVal, envelopeSender string) string {
	if headerVal == "" {
		return envelopeSender
	}

	cleanName := strings.Trim(headerVal, "\"")
	if strings.Contains(cleanName, "<") {
		return headerVal
	}

	return fmt.Sprintf("\"%s\" <%s>", strings.TrimSpace(cleanName), envelopeSender)
}

func parseHeaderLine(line string, headers map[string]string) bool {
	keyRaw, valRaw, found := strings.Cut(line, ":")
	if !found {
		return false
	}

	// Key must have no spaces and only contain valid header characters
	key := strings.TrimSpace(keyRaw)
	if strings.ContainsAny(key, " \t") {
		return false
	}
	if len(key) == 0 {
		return false
	}

	keyLower := strings.ToLower(key)
	val := strings.TrimSpace(valRaw)

	switch keyLower {
	case "to", "toa":
		upperVal := strings.ToUpper(val)
		if strings.Contains(upperVal, strings.ToUpper(config.NJE.RunAsUser)) &&
			strings.Contains(upperVal, strings.ToUpper(config.Routing.SMTPNode)) {
			return true
		}
		addHeader(headers, "to", normalizeAddresses(val))
	case "cc":
		addHeader(headers, "cc", normalizeAddresses(val))
	case "bcc":
		addHeader(headers, "bcc", normalizeAddresses(val))
	case "subject":
		if headers["subject"] == "" {
			headers["subject"] = val
		}
	case "date":
		if headers["date"] == "" {
			headers["date"] = val
		}
	case "from", "frm":
		if headers["from"] == "" {
			headers["from"] = val
		}
	case "message-id":
		if headers["message-id"] == "" {
			headers["message-id"] = val
		}
	default:
		return false
	}
	return true
}

func addHeader(headers map[string]string, key, val string) {
	if headers[key] == "" {
		headers[key] = val
	} else {
		headers[key] += ", " + val
	}
}
