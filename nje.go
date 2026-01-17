package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func parseAddress(addr string) (user, node string) {
	parts := strings.Split(addr, "@")
	if len(parts) > 0 {
		user = parts[0]
	}
	if len(parts) > 1 {
		node = parts[1]
	}
	return
}

func deriveNJEFilename(email string) (fn, ft string) {
	user, _ := parseAddress(email)

	fn = strings.ToUpper(user)
	if len(fn) > 8 {
		fn = fn[:8]
	}
	if fn == "" || fn == "UNKNOWN" {
		fn = "NOTE"
	}

	ft = "NOTE"
	return
}

func isValidCMSUser(user string) bool {
	u := strings.ToLower(user)
	if u == "root" || u == "operator" || u == "system" || strings.HasPrefix(u, "guest") {
		return false
	}
	if len(u) == 0 || len(u) > 8 {
		return false
	}
	for _, r := range u {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func sendErrorNotification(failedRecipient, reason, disposition, savedPath string) {
	if config.Routing.ErrorRecipient == "" {
		return
	}

	adminUser := config.Routing.ErrorRecipient
	adminNode := config.Routing.RSCSNode

	errPath := filepath.Join(os.TempDir(), fmt.Sprintf("error_%d.txt", time.Now().UnixNano()))

	f, _ := os.Create(errPath)
	fmt.Fprintf(f, "SYSTEM NOTIFICATION: DELIVERY FAILURE\n")
	fmt.Fprintf(f, "Recipient: %s\nReason: %s\nAction: %s\n", failedRecipient, reason, disposition)
	if disposition == "Saved" {
		fmt.Fprintf(f, "Location: %s\n", savedPath)
	}
	f.Close()

	sendOverNJE(strings.ToUpper(adminUser), strings.ToUpper(adminNode), errPath, "ERROR", "LOG", "")
	os.Remove(errPath)
}

func handleDispatch(recipient, filePath, cmsFn, cmsFt, subject string) {
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return
	}
	user, domain := parts[0], parts[1]

	if !strings.EqualFold(domain, config.Server.Domain) {
		action := strings.ToLower(config.Routing.DefaultAction)
		reason := fmt.Sprintf("domain %s not configured (only %s supported)", domain, config.Server.Domain)

		switch action {
		case "save":
			log.Printf("routing failed for %s. saved at %s", recipient, filePath)
			sendErrorNotification(recipient, reason, "Saved", filePath)
		case "delete":
			sendErrorNotification(recipient, reason, "Deleted", "")
		default:
			sendErrorNotification(recipient, reason, "Ignored", "")
		}
		return
	}
	// We are good to go, target node is our configured node.
	targetNode := config.Routing.RSCSNode

	validUser := isValidCMSUser(user)

	if !validUser {
		action := strings.ToLower(config.Routing.DefaultAction)
		reason := fmt.Sprintf("invalid CMS userid (%s)", user)

		switch action {
		case "save":
			log.Printf("routing failed for %s. saved at %s", recipient, filePath)
			sendErrorNotification(recipient, reason, "Saved", filePath)
		case "delete":
			sendErrorNotification(recipient, reason, "Deleted", "")
		default:
			sendErrorNotification(recipient, reason, "Ignored", "")
		}
		return
	}
	cmsUser := strings.ToUpper(user)
	if err := sendOverNJE(cmsUser, targetNode, filePath, cmsFn, cmsFt, subject); err != nil {
		log.Printf("nje error sending to %s@%s: %v", cmsUser, targetNode, err)
	} else {
		log.Printf("sent %s %s to %s@%s", cmsFn, cmsFt, cmsUser, targetNode)
	}
}

func sendOverNJE(user, node, file, cmsFn, cmsFt, subject string) error {
	if strings.Contains(user, "--") {
		parts := strings.SplitN(user, "--", 2)
		if len(parts) == 2 {
			user = parts[0]
			node = parts[1]
		}
	}

	target := fmt.Sprintf("%s@%s", user, node)
	log.Printf("DEBUG: sendOverNJE target=%s fn=%s ft=%s subject=%q", target, cmsFn, cmsFt, subject)

	binary := config.NJE.BinaryPath
	if binary == "" {
		binary = "punch"
	}

	args := []string{target, "-fn", cmsFn, cmsFt}

	if config.NJE.RunAsUser != "" {
		args = append(args, "-u", config.NJE.RunAsUser)
	}

	tagStr := config.NJE.Tag
	if subject != "" {
		if tagStr != "" {
			tagStr = fmt.Sprintf("%s (%s)", tagStr, subject)
		} else {
			tagStr = fmt.Sprintf("(%s)", subject)
		}
	}

	if tagStr != "" {
		args = append(args, "-tag", tagStr)
	}

	if config.NJE.Distribution != "" {
		args = append(args, "-dist", config.NJE.Distribution)
	}

	if config.NJE.Class != "" {
		args = append(args, "-class", config.NJE.Class)
	}

	if config.NJE.Form != "" {
		args = append(args, "-form", config.NJE.Form)
	}

	args = append(args, "-rawpun", file)

	cmd := exec.Command(binary, args...)
	log.Printf("DEBUG: Executing: %s %v", binary, args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s | output: %s", err, string(out))
	}
	return nil
}
