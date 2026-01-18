package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-smtp"
)

var (
	config        Config
	htmlTagRegex  = regexp.MustCompile("<[^>]*>")
	htmlLinkRegex = regexp.MustCompile(`(?i)<a[^>]*href=["']([^"']*)["'][^>]*>((?s).*?)</a>`)
	cmsUserRegex  = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// NewSession creates a new SMTP session.
func (bk *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		RemoteAddr: c.Conn().RemoteAddr().String(),
		HelloName:  c.Hostname(),
		Conn:       c.Conn(),
	}, nil
}

// AuthPlain handles PLAIN authentication (not implemented).
func (s *Session) AuthPlain(username, password string) error {
	return smtp.ErrAuthUnsupported
}

// Mail handles the MAIL FROM command.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.From = from
	return nil
}

// Rcpt handles the RCPT TO command.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	parts := strings.Split(to, "@")
	if len(parts) != 2 {
		return &smtp.SMTPError{
			Code:    501,
			Message: "Bad address syntax",
		}
	}
	domain := parts[1]

	if !strings.EqualFold(domain, config.Server.Domain) {
		log.Printf("Skipping %s: domain mismatch (expected %s) (From: %s via %s)", to, config.Server.Domain, s.From,
			s.Conn.RemoteAddr().String())
		return &smtp.SMTPError{
			Code:    550,
			Message: "Relay access denied",
		}
	}
	s.To = append(s.To, to)
	return nil
}

// Reset resets the session state.
func (s *Session) Reset() {
	s.From = ""
	s.To = nil
}

// Logout handles the QUIT command.
func (s *Session) Logout() error {
	return nil
}

// Data parses the email, formatting it as an EBCDIC PUNCH file.
func (s *Session) Data(r io.Reader) error {
	// Read entire message for security checks and parsing
	msgBytes, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	pass, reason := checkEmailSecurity(s.RemoteAddr, s.HelloName, s.From, msgBytes)

	mr, err := mail.CreateReader(bytes.NewReader(msgBytes))
	if err != nil {
		log.Printf("create reader error: %v", err)
		return err
	}

	subject := mr.Header.Get("Subject")
	fromHeader := mr.Header.Get("From")
	fromList, err := mr.Header.AddressList("From")
	if err == nil && len(fromList) > 0 {
		addr := fromList[0]
		if addr.Name != "" {
			fromHeader = fmt.Sprintf("%s (%s)", addr.Address, addr.Name)
		} else {
			fromHeader = addr.Address
		}
	}

	emailTime := time.Now()
	if dateHeader := mr.Header.Get("Date"); dateHeader != "" {
		formats := []string{
			time.RFC1123Z,
			time.RFC1123,
			"Mon, 2 Jan 2006 15:04:05 -0700",
			"Mon, 2 Jan 2006 15:04:05 MST",
			"2 Jan 2006 15:04:05 -0700",
		}
		for _, format := range formats {
			if parsed, err := time.Parse(format, dateHeader); err == nil {
				emailTime = parsed
				break
			}
		}
	}

	var bodyBuf bytes.Buffer
	var htmlBuf bytes.Buffer
	hasPlain := false

	if !pass {
		banner := "********************************************************************************\n" +
			"*                                                                              *\n" +
			"*                     WARNING: SENDER IDENTITY UNVERIFIED                      *\n" +
			"*                                                                              *\n" +
			fmt.Sprintf("* Reason: %-60s *\n", reason) +
			"*                                                                              *\n" +
			"********************************************************************************\n"
		bodyBuf.WriteString(banner)
	}

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("read part error: %v", err)
			break
		}

		ct := p.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(ct)

		switch mediaType {
		case "text/plain":
			if _, err := io.Copy(&bodyBuf, p.Body); err != nil {
				log.Printf("body read error: %v", err)
			}
			bodyBuf.WriteString("\n")
			hasPlain = true
		case "text/html":
			if _, err := io.Copy(&htmlBuf, p.Body); err != nil {
				log.Printf("html body read error: %v", err)
			}
			htmlBuf.WriteString("\n")
		}
	}

	if !hasPlain && htmlBuf.Len() > 0 {
		htmlStr := htmlBuf.String()
		htmlStr = htmlLinkRegex.ReplaceAllStringFunc(htmlStr, func(match string) string {
			parts := htmlLinkRegex.FindStringSubmatch(match)
			if len(parts) >= 3 {
				url := html.UnescapeString(parts[1])
				text := parts[2]
				return fmt.Sprintf("%s (%s)", text, url)
			}
			return match
		})
		stripped := htmlTagRegex.ReplaceAllString(htmlStr, "")
		bodyBuf.WriteString(stripped)
	}

	ebcdicBuf, err := generateEbcdicNote(s.From, s.To, subject, fromHeader, &bodyBuf, emailTime)
	if err != nil {
		log.Printf("ebcdic generation error: %v", err)
		return err
	}

	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("NOTE_%d.bin", time.Now().UnixNano()))
	if err := os.WriteFile(tmpPath, ebcdicBuf.Bytes(), 0644); err != nil {
		log.Printf("failed to write note file: %v", err)
		return err
	}

	fn, ft := deriveNJEFilename(s.From)

	for _, recipient := range s.To {
		handleDispatch(recipient, tmpPath, fn, ft, subject)
	}
	os.Remove(tmpPath)

	return nil
}

func main() {
	args := os.Args[1:]
	configPath := "config.toml"
	if len(args) > 0 {
		configPath = args[0]
	}
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		log.Fatal(err)
	}

	// Deprecate BinaryPath in favor of more obvious PunchPath
	if config.NJE.PunchPath == "" {
		if config.NJE.BinaryPath != "" {
			log.Printf("Binary Path is deprecated, use Punch Path instead, see link below for more info. ")
			log.Printf("https://raw.githubusercontent.com/Rudi9719/RSCSMail/refs/heads/master/config.toml.dist")
			config.NJE.PunchPath = config.NJE.BinaryPath
		}
	}

	// Deprecate Interval for fsnotify
	if config.Spool.Interval != "" {
		log.Printf("Interval is deprecated, see link below for more info. ")
		log.Printf("https://raw.githubusercontent.com/Rudi9719/RSCSMail/refs/heads/master/config.toml.dist")
	}

	if err := ensureDKIMKey("dkim_private.pem"); err != nil {
		log.Fatalf("Failed to ensure DKIM key: %v", err)
	}

	go ensureDMARCRecord()
	go ensureSPFRecord()

	if config.Spool.Directory != "" {
		go StartSpoolMonitor()
	}

	be := &Backend{}
	s := smtp.NewServer(be)
	s.Addr = config.Server.ListenAddr
	s.Domain = config.Server.Domain
	s.MaxMessageBytes = 20 * 1024 * 1024
	s.AllowInsecureAuth = true

	if config.Server.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(config.Server.TLSCertFile, config.Server.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certs: %v", err)
		} else {
			s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	log.Printf("RSCS Mail is listening on %s (EHLO %s)", s.Addr, s.Domain)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}
