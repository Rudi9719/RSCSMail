package main

import (
	"testing"
)

func TestParseSpoolData(t *testing.T) {
	originalConfig := config
	defer func() { config = originalConfig }()

	config = Config{
		Routing: RoutingConfig{
			SMTPNode:     "SMTP",
			DkimSelector: "default",
			Domains: []DomainPair{
				{
					INetDomain: "example.org",
					RSCSNode:   "EXAMPLE",
				},
				{
					INetDomain: "example.com",
					RSCSNode:   "NODE2",
				},
			},
		},
	}

	tests := []struct {
		name           string
		content        string
		receiveOutput  string
		rscsSender     string
		expectedSender string
		expectedDate   string
	}{
		{
			name: "Fallback to From Header",
			content: "Date: 17 Jan 2026 01:10:06 GMT\r\n" +
				"From: TestUser <testuser@example.com>\r\n" +
				"To: test@example.com\r\n" +
				"Subject: Test\r\n\r\n" +
				"Body content",
			receiveOutput:  "File 0001 from TESTUSER at EXAMPLE sent to ...",
			expectedSender: "testuser@example.org",
			expectedDate:   "17 Jan 2026 01:10:06 GMT",
		},
		{
			name: "Fallback to From Header NODE2",
			content: "Date: 17 Jan 2026 01:10:06 GMT\r\n" +
				"From: TestUser <testuser@example.com>\r\n" +
				"To: test@example.com\r\n" +
				"Subject: Test\r\n\r\n" +
				"Body content",
			receiveOutput:  "File 0001 from TESTUSER at NODE2 sent to ...",
			expectedSender: "testuser@example.com",
			expectedDate:   "17 Jan 2026 01:10:06 GMT",
		},
		{
			name: "Use Receive Output if Available",
			content: "Date: 17 Jan 2026 01:10:06 GMT\r\n" +
				"From: TestUser <testuser@example.com>\r\n" +
				"To: test@example.com\r\n" +
				"Subject: Test\r\n\r\n" +
				"Body content",
			receiveOutput:  "File 0001 from SOMEUSER at EXAMPLE sent to ...",
			expectedSender: "someuser@example.org",
			expectedDate:   "17 Jan 2026 01:10:06 GMT",
		},
		{
			name: "Date Header Parsing",
			content: "Date: 17 January 26, 01:10:06 GMT\r\n" + // Format from the log
				"From: TestUser <testuser@example.com>\r\n" +
				"To: test@example.com\r\n\r\n",
			receiveOutput:  "File 0001 from TESTUSER at EXAMPLE sent to ...",
			expectedSender: "testuser@example.org",
			expectedDate:   "17 January 26, 01:10:06 GMT",
		},
		{
			name: "RSCS Sender Precedence",
			content: "From: TestUser <testuser@example.com>\r\n" +
				"To: test@example.com\r\n\r\n",
			receiveOutput:  "File 0001 from authoritative at EXAMPLE sent to ...",
			expectedSender: "authoritative@example.org",
			expectedDate:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, _, _, _, headers, _ := parseSpoolData([]byte(tt.content), tt.receiveOutput, tt.rscsSender)
			if sender != tt.expectedSender {
				t.Errorf("expected sender %s, got %s", tt.expectedSender, sender)
			}
			if tt.expectedDate != "" && headers["date"] != tt.expectedDate {
				t.Errorf("expected date %s, got %s", tt.expectedDate, headers["date"])
			}
		})
	}
}

func TestResolveNode(t *testing.T) {
	originalConfig := config
	defer func() { config = originalConfig }()

	config = Config{
		Routing: RoutingConfig{
			SMTPNode:     "SMTP",
			DkimSelector: "default",
			Domains: []DomainPair{
				{
					INetDomain: "example.org",
					RSCSNode:   "EXAMPLE",
				},
				{
					INetDomain: "example.com",
					RSCSNode:   "NODE2",
				},
			},
		},
	}

	tests := []struct {
		domain       string
		expectedNode string
	}{
		{"example.org", "EXAMPLE"},
		{"EXAMPLE.ORG", "EXAMPLE"},
		{"other.com", ""},
		{"unknown.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := resolveNode(tt.domain); got != tt.expectedNode {
				t.Errorf("resolveNode(%q) = %q; want %q", tt.domain, got, tt.expectedNode)
			}
		})
	}
}
