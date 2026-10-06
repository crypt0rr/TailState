package notify

import (
	"regexp"
	"strconv"
)

// collectorNouns names the resources of each collector in notifications,
// singular and plural. Collectors with one fixed resource (the policy, DNS
// configuration, settings, contacts, and log streaming) have no noun: the
// resource's own name ("Tailnet policy") already says what it is.
var collectorNouns = map[string][2]string{
	"devices":        {"device", "devices"},
	"device_details": {"device", "devices"},
	"users":          {"user", "users"},
	"user_invites":   {"user invite", "user invites"},
	"keys":           {"key", "keys"},
	"webhooks":       {"webhook", "webhooks"},
	"posture":        {"posture integration", "posture integrations"},
	"services":       {"service", "services"},
	"oauth_apps":     {"OAuth app", "OAuth apps"},
	"dns":            {},
	"policy":         {},
	"settings":       {},
	"contacts":       {},
	"log_streaming":  {},
}

// typeSpans is the "(device)" type cue after a resource name, or nothing for
// a collector with one fixed resource. An unknown collector is shown as is,
// escaped like any value.
func typeSpans(collector string) []Span {
	nouns, known := collectorNouns[collector]
	switch {
	case !known:
		return []Span{lit(" ("), txt(collector), lit(")")}
	case nouns[0] == "":
		return nil
	}
	return []Span{lit(" (" + nouns[0] + ")")}
}

// countSpans is "12 devices" or "1 key" for count resources of a
// collector, or "12 example resources" for an unknown collector.
func countSpans(collector string, count int) []Span {
	if nouns := collectorNouns[collector]; nouns[0] != "" {
		return []Span{lit(plural(count, nouns[0], nouns[1]))}
	}
	word := " resources"
	if count == 1 {
		word = " resource"
	}
	return []Span{lit(strconv.Itoa(count) + " "), txt(collector), lit(word)}
}

// magicDNSName matches a device's MagicDNS name, "host.tailnet-name.ts.net".
var magicDNSName = regexp.MustCompile(`^([^.]+)\.[A-Za-z0-9-]+\.ts\.net\.?$`)

// shortDeviceName strips the tailnet's MagicDNS suffix from a device name:
// every device of a tailnet shares it, so it only costs width and budget.
// History, the API, and evidence packs keep the full name.
func shortDeviceName(name string) string {
	if match := magicDNSName.FindStringSubmatch(name); match != nil {
		return match[1]
	}
	return name
}

// displayName is the name a change is listed under in a notification.
func displayName(collector, name string) string {
	if collector == "devices" || collector == "device_details" {
		return shortDeviceName(name)
	}
	return name
}
