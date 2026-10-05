package model

import (
	"encoding/json"
	"sort"
)

// DNS snapshots exist in two shapes. Releases before the dns/configuration
// migration stored the four legacy endpoints side by side:
//
//	{"nameservers":{"dns":[...]},"preferences":{"magicDNS":b},
//	 "searchpaths":{"searchPaths":[...]},"split-dns":{"domain":[...]}}
//
// The configuration endpoint returns one object that also carries
// per-resolver useWithExitNode and the overrideLocalDNS preference:
//
//	{"nameservers":[{"address":a,"useWithExitNode":b}],"preferences":{...},
//	 "searchPaths":[...],"splitDNS":{"domain":[{"address":a,...}]}}
//
// The collector falls back to the legacy endpoints when the configuration
// endpoint returns 404, so a snapshot can change shape on upgrade or on a
// fallback. ShapeTransition lets the store compare such a pair only on the
// fields both shapes express, so a shape change alone is silent while a real
// nameserver, search-path, split-DNS, or MagicDNS change is still reported.

const (
	dnsShapeUnknown = iota
	dnsShapeLegacy
	dnsShapeConfiguration
)

// ShapeTransition reports whether oldRaw and newRaw are canonical snapshots of
// the same collector in different upstream shapes. When they are, it returns
// both values projected onto the fields the shapes have in common, in
// canonical JSON, for comparison and diffing.
func ShapeTransition(collector string, oldRaw, newRaw []byte) (oldComparable, newComparable []byte, transition bool) {
	if collector != "dns" {
		return nil, nil, false
	}
	var oldValue, newValue map[string]any
	if json.Unmarshal(oldRaw, &oldValue) != nil || json.Unmarshal(newRaw, &newValue) != nil {
		return nil, nil, false
	}
	oldShape, newShape := dnsShape(oldValue), dnsShape(newValue)
	if oldShape == dnsShapeUnknown || newShape == dnsShapeUnknown || oldShape == newShape {
		return nil, nil, false
	}
	oldProjection, oldUnknown := projectDNS(oldValue, oldShape)
	newProjection, newUnknown := projectDNS(newValue, newShape)
	// A section the legacy collector could not read (recorded as
	// {"unsupported": true}) carries no comparable value; exclude it from
	// both sides instead of reporting its first observation as drift.
	for section := range oldUnknown {
		delete(oldProjection, section)
		delete(newProjection, section)
	}
	for section := range newUnknown {
		delete(oldProjection, section)
		delete(newProjection, section)
	}
	oldComparable, _, err := canonical(oldProjection)
	if err != nil {
		return nil, nil, false
	}
	newComparable, _, err = canonical(newProjection)
	if err != nil {
		return nil, nil, false
	}
	return oldComparable, newComparable, true
}

func dnsShape(value map[string]any) int {
	if value == nil {
		return dnsShapeUnknown
	}
	if _, ok := value["split-dns"]; ok {
		return dnsShapeLegacy
	}
	if _, ok := value["searchpaths"]; ok {
		return dnsShapeLegacy
	}
	if _, ok := value["nameservers"].(map[string]any); ok {
		return dnsShapeLegacy
	}
	if _, ok := value["splitDNS"]; ok {
		return dnsShapeConfiguration
	}
	if _, ok := value["searchPaths"]; ok {
		return dnsShapeConfiguration
	}
	if _, ok := value["nameservers"].([]any); ok {
		return dnsShapeConfiguration
	}
	return dnsShapeUnknown
}

// projectDNS maps either shape onto
// {"nameservers":[addr...],"magicDNS":b,"searchPaths":[...],"splitDNS":{domain:[addr...]}}
// and reports the sections that were unknown in a legacy snapshot.
func projectDNS(value map[string]any, shape int) (map[string]any, map[string]struct{}) {
	unknown := map[string]struct{}{}
	out := map[string]any{}
	if shape == dnsShapeLegacy {
		section := func(key, name string) (map[string]any, bool) {
			object, _ := value[key].(map[string]any)
			if legacyUnsupported(object) {
				unknown[name] = struct{}{}
				return nil, false
			}
			return object, true
		}
		if object, ok := section("nameservers", "nameservers"); ok {
			out["nameservers"] = stringValues(object["dns"])
		}
		if object, ok := section("preferences", "magicDNS"); ok {
			out["magicDNS"] = boolValue(object["magicDNS"])
		}
		if object, ok := section("searchpaths", "searchPaths"); ok {
			out["searchPaths"] = stringValues(object["searchPaths"])
		}
		if object, ok := section("split-dns", "splitDNS"); ok {
			split := map[string]any{}
			for domain, resolvers := range object {
				if addresses := sortedStrings(stringValues(resolvers)); len(addresses) > 0 {
					split[domain] = addresses
				}
			}
			out["splitDNS"] = split
		}
		return out, unknown
	}
	out["nameservers"] = resolverAddresses(value["nameservers"])
	preferences, _ := value["preferences"].(map[string]any)
	out["magicDNS"] = boolValue(preferences["magicDNS"])
	out["searchPaths"] = stringValues(value["searchPaths"])
	split := map[string]any{}
	if object, ok := value["splitDNS"].(map[string]any); ok {
		for domain, resolvers := range object {
			if addresses := sortedStrings(resolverAddresses(resolvers)); len(addresses) > 0 {
				split[domain] = addresses
			}
		}
	}
	out["splitDNS"] = split
	return out, unknown
}

func legacyUnsupported(object map[string]any) bool {
	if len(object) != 1 {
		return false
	}
	unsupported, ok := object["unsupported"].(bool)
	return ok && unsupported
}

func resolverAddresses(value any) []any {
	list, _ := value.([]any)
	out := make([]any, 0, len(list))
	for _, entry := range list {
		switch resolver := entry.(type) {
		case map[string]any:
			if address, ok := resolver["address"].(string); ok {
				out = append(out, address)
			}
		case string:
			out = append(out, resolver)
		}
	}
	return out
}

func stringValues(value any) []any {
	list, _ := value.([]any)
	out := make([]any, 0, len(list))
	for _, entry := range list {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func sortedStrings(values []any) []any {
	sort.SliceStable(values, func(i, j int) bool {
		left, _ := values[i].(string)
		right, _ := values[j].(string)
		return left < right
	})
	return values
}

func boolValue(value any) bool {
	b, _ := value.(bool)
	return b
}
