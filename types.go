package main

import (
	"net"
)

// Config holds the application configuration.
type Config struct {
	Server  ServerConfig  `toml:"server"`
	NJE     NJEConfig     `toml:"nje"`
	Routing RoutingConfig `toml:"routing"`
	Spool   SpoolConfig   `toml:"spool"`
}

// SpoolConfig defines settings for the outbound email spool monitor.
type SpoolConfig struct {
	Directory  string `toml:"directory"`
	Interval   string `toml:"interval"`
	TargetSMTP string `toml:"target_smtp"`
	TargetUser string `toml:"target_user"`
	TargetPass string `toml:"target_pass"`
}

// ServerConfig defines the SMTP server settings.
type ServerConfig struct {
	ListenAddr  string `toml:"listen_addr"`
	Domain      string `toml:"domain"` // EHLO identity
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`
}

// NJEConfig defines constraints and command options for the NJE/Punch interface.
type NJEConfig struct {
	BinaryPath   string `toml:"binary_path"`
	PunchPath    string `toml:"punch_path"`
	ReceivePath  string `toml:"receive_path"`
	RunAsUser    string `toml:"run_as_user"`
	Tag          string `toml:"tag"`
	Distribution string `toml:"distribution"`
	Class        string `toml:"class"`
	Form         string `toml:"form"`
}

// RoutingConfig defines how emails are mapped to NJE nodes and users.
type RoutingConfig struct {
	DefaultAction  string `toml:"default_action"`
	ErrorRecipient string `toml:"error_recipient"`
	NJESender      string `toml:"nje_sender"`
	RSCSNode       string `toml:"rscs_node"`
	SMTPNode       string `toml:"smtp_node"`
	DkimKeyPath    string `toml:"dkim_key_path"`
	DkimSelector   string `toml:"dkim_selector"`
}

// Backend implements smtp.Backend.
type Backend struct{}

// Session implements smtp.Session.
type Session struct {
	From       string
	To         []string
	RemoteAddr string
	HelloName  string
	Conn       net.Conn
}

// Attachment struct to hold extracted attachments
type Attachment struct {
	Filename string
	Data     []byte
}

// AttachmentInfo struct to hold attachment info
type AttachmentInfo struct {
	Filename string
	Data     []byte
	Fn       string
	Ft       string
}

type nameInfo struct {
	baseName  string
	extension string
}
