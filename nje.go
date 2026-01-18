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
		domain_parts := strings.Split(parts[1], ".")
		node = domain_parts[0]
	}
	return
}

func deriveNJEFilename(email string) (fn, ft string) {
	user, node := parseAddress(email)

	clean := func(s string) string {
		res := cmsUserRegex.ReplaceAllString(strings.ToUpper(s), "")
		if len(res) > 8 {
			return res[:8]
		}
		return res
	}

	fn = clean(user)
	ft = clean(node)

	return
}

func deriveCMSShortNames(filenames []string) []string {
	clean := func(s string) string {
		return cmsUserRegex.ReplaceAllString(strings.ToUpper(s), "")
	}

	collisionSuffix := func(index int) string {
		if index <= 0 {
			return ""
		}
		if index <= 0x0F {
			return fmt.Sprintf("-%X", index)
		}
		if index <= 0xFF {
			return fmt.Sprintf("%02X", index)
		}
		return fmt.Sprintf("%X", index)
	}

	type nameInfo struct {
		baseName  string
		extension string
	}
	infos := make([]nameInfo, len(filenames))
	baseCount := make(map[string]int)

	for i, filename := range filenames {
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		cleanBase := clean(base)
		if cleanBase == "" {
			cleanBase = "FILE"
		}
		infos[i] = nameInfo{baseName: cleanBase, extension: ext}
		baseCount[cleanBase]++
	}

	result := make([]string, len(filenames))
	baseIndex := make(map[string]int)

	for i, info := range infos {
		count := baseCount[info.baseName]

		if count == 1 {
			shortName := info.baseName
			if len(shortName) > 8 {
				shortName = shortName[:8]
			}
			result[i] = shortName
		} else {
			baseIndex[info.baseName]++
			idx := baseIndex[info.baseName]
			suffix := collisionSuffix(idx)

			shortBase := info.baseName
			if len(shortBase) > 6 {
				shortBase = shortBase[:6]
			}
			result[i] = shortBase + suffix
		}
	}

	return result
}

func isValidCMSUser(user string) bool {
	u := strings.ToLower(user)
	if u == "root" || u == "operator" || u == "system" || strings.HasPrefix(u, "guest") {
		return false
	}
	if len(u) == 0 || len(u) > 8 {
		return false
	}
	return !cmsUserRegex.MatchString(u)
}

func sendErrorNotification(failedRecipient, reason, disposition, savedPath string) {
	if config.Routing.ErrorRecipient == "" {
		return
	}

	adminUserUpper := strings.ToUpper(config.Routing.ErrorRecipient)
	adminNodeUpper := strings.ToUpper(config.Routing.RSCSNode)
	actionLower := strings.ToLower(config.Routing.DefaultAction)

	errPath := filepath.Join(os.TempDir(), fmt.Sprintf("error_%d.txt", time.Now().UnixNano()))

	f, _ := os.Create(errPath)
	fmt.Fprintf(f, "SYSTEM NOTIFICATION: DELIVERY FAILURE\n")
	fmt.Fprintf(f, "Recipient: %s\nReason: %s\nAction: %s\n", failedRecipient, reason, disposition)
	if disposition == "Saved" {
		fmt.Fprintf(f, "Location: %s\n", savedPath)
	}
	f.Close()

	sendOverNJE(adminUserUpper, adminNodeUpper, errPath, "ERROR", "LOG", "")
	if actionLower == "delete" {
		os.Remove(errPath)
	}
}

func handleDispatch(recipient, filePath, cmsFn, cmsFt, subject string) {
	actionLower := strings.ToLower(config.Routing.DefaultAction)
	targetNode := config.Routing.RSCSNode

	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return
	}
	user, domain := parts[0], parts[1]

	if !strings.EqualFold(domain, config.Server.Domain) {
		reason := fmt.Sprintf("domain %s not configured (only %s supported)", domain, config.Server.Domain)

		switch actionLower {
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

	validUser := isValidCMSUser(user)

	if !validUser {
		reason := fmt.Sprintf("invalid CMS userid (%s)", user)

		switch actionLower {
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

	cmsUserUpper := strings.ToUpper(user)

	if err := sendOverNJE(cmsUserUpper, targetNode, filePath, cmsFn, cmsFt, subject); err != nil {
		log.Printf("nje error sending to %s@%s: %v", cmsUserUpper, targetNode, err)
	} else {
		log.Printf("sent %s %s to %s@%s", cmsFn, cmsFt, cmsUserUpper, targetNode)
	}
}

func sendOverNJE(user, node, file, cmsFn, cmsFt, subject string) error {
	binary := config.NJE.PunchPath
	if strings.Contains(user, "--") {
		parts := strings.SplitN(user, "--", 2)
		if len(parts) == 2 {
			user = parts[0]
			node = parts[1]
		}
	}

	target := fmt.Sprintf("%s@%s", user, node)
	log.Printf("DEBUG: sendOverNJE target=%s fn=%s ft=%s subject=%q", target, cmsFn, cmsFt, subject)

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
