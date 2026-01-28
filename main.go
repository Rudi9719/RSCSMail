/*
RSCS Mail bridges modern mail requirements set by Google to RSCS for Vintage Mainframes.
Specifically this was designed to bring 2025 support to IBM PROFS.
Along the way support for CMS Notes, and eventually any file with proper headers emerged.

It is released under the Unlicense because go.dev rejected the WTFPL.

Usage:

	rscsmail [/path/to/config.toml]

The path to config is optional, and defaults to ./config.toml
Please ensure your working directory is secure unless config.toml specifies a secure path for DKIM keys.
*/
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
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-smtp"
)

var (
	config          Config
	htmlTagRegex    = regexp.MustCompile("<[^>]*>")
	htmlLinkRegex   = regexp.MustCompile(`(?i)<a[^>]*href=["']([^"']*)["'][^>]*>((?s).*?)</a>`)
	cmsUserRegex    = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	processingFiles sync.Map
)

// NewSession creates a new SMTP session.
func (bk *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		RemoteAddr: c.Conn().RemoteAddr().String(),
		HelloName:  config.Server.EhloIdentity,
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
	emailTime := time.Now()
	var bodyBuf bytes.Buffer
	var htmlBuf bytes.Buffer
	var attachments []Attachment
	var attachInfos []AttachmentInfo
	hasPlain := false

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

	if !pass {
		banner := "*****************************************************************************\n" +
			"*                                                                           *\n" +
			"*                     WARNING: SENDER IDENTITY UNVERIFIED                   *\n" +
			"*                                                                           *\n" +
			fmt.Sprintf("* Reason: %-65s *\n", reason) +
			"*                                                                           *\n" +
			"*****************************************************************************\n"
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
		mediaType, ctParams, _ := mime.ParseMediaType(ct)

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
		case "multipart/alternative", "multipart/mixed", "multipart/related":
		default:
			_, dispParams, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
			filename := dispParams["filename"]
			if filename == "" {
				filename = ctParams["name"]
			}
			if filename == "" {
				parts := strings.Split(mediaType, "/")
				if len(parts) == 2 {
					filename = "attach." + parts[1]
				} else {
					filename = "attach.bin"
				}
			}

			data, err := io.ReadAll(p.Body)
			if err != nil {
				log.Printf("Attachment read error for %s: %v", filename, err)
				continue
			}

			if len(data) > 0 {
				attachments = append(attachments, Attachment{Filename: filename, Data: data})
				log.Printf("Extracted attachment: %s (%d bytes)", filename, len(data))
			}
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

	// Derive DOS 8.3 style short names for all attachments
	filenames := make([]string, len(attachments))
	for i, attach := range attachments {
		filenames[i] = attach.Filename
	}
	shortNames := deriveCMSShortNames(filenames)

	for i, attach := range attachments {
		attachFn := shortNames[i]

		ext := strings.TrimPrefix(filepath.Ext(attach.Filename), ".")
		if ext == "" {
			ext = "BIN"
		}
		attachFt := strings.ToUpper(cmsUserRegex.ReplaceAllString(ext, ""))
		if len(attachFt) > 8 {
			attachFt = attachFt[:8]
		}
		if attachFt == "" {
			attachFt = "BIN"
		}

		attachInfos = append(attachInfos, AttachmentInfo{
			Filename: attach.Filename,
			Data:     attach.Data,
			Fn:       attachFn,
			Ft:       attachFt,
		})
	}

	if len(attachInfos) > 0 {
		bodyBuf.WriteString("\n")
		bodyBuf.WriteString("********************************************************************************\n")
		bodyBuf.WriteString("ATTACHMENTS:\n")
		for _, info := range attachInfos {
			bodyBuf.WriteString(fmt.Sprintf("  %8s %s was %s\n", info.Fn, info.Ft, info.Filename))
		}
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
	defer os.Remove(tmpPath)

	for _, info := range attachInfos {
		attachPath := filepath.Join(os.TempDir(), fmt.Sprintf("ATTACH_%d.bin", time.Now().UnixNano()))
		if err := os.WriteFile(attachPath, info.Data, 0644); err != nil {
			log.Printf("failed to write attachment file: %v", err)
			continue
		}

		attachSubject := fmt.Sprintf("Attachment: %s", info.Filename)
		for _, recipient := range s.To {
			handleDispatch(recipient, attachPath, info.Fn, info.Ft, attachSubject)
		}
		go os.Remove(attachPath)
	}

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

	// Check for ehlo_identity
	if config.Server.EhloIdentity == "" {
		config.Server.EhloIdentity = config.Server.Domain
		log.Printf("ehlo identity not set, see link below for more info. ")
		log.Printf("https://raw.githubusercontent.com/Rudi9719/RSCSMail/refs/heads/master/config.toml.dist")
	}

	if err := ensureDKIMKey(config.Routing.DkimKeyPath); err != nil {
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
