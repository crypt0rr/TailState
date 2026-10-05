package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/crypt0rr/tailstate/internal/store"
)

// htmlDocument parses a rendered page so tests can assert structure and
// attributes instead of matching substrings.
func htmlDocument(t *testing.T, body string) *html.Node {
	t.Helper()
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse rendered HTML: %v", err)
	}
	return document
}

func htmlAttr(node *html.Node, name string) (string, bool) {
	for _, attribute := range node.Attr {
		if attribute.Key == name {
			return attribute.Val, true
		}
	}
	return "", false
}

func htmlHasClass(node *html.Node, class string) bool {
	value, _ := htmlAttr(node, "class")
	for _, candidate := range strings.Fields(value) {
		if candidate == class {
			return true
		}
	}
	return false
}

func htmlElements(root *html.Node, match func(*html.Node) bool) []*html.Node {
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && match(node) {
			out = append(out, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return out
}

func htmlTag(tag string) func(*html.Node) bool {
	return func(node *html.Node) bool { return node.Data == tag }
}

func htmlText(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(builder.String()), " ")
}

func htmlAncestor(node *html.Node, tag string) *html.Node {
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == tag {
			return parent
		}
	}
	return nil
}

// accessibleName approximates the accessible-name computation for the
// controls TailState renders: aria-label wins, otherwise visible text.
func accessibleName(node *html.Node) string {
	if label, ok := htmlAttr(node, "aria-label"); ok && strings.TrimSpace(label) != "" {
		return strings.TrimSpace(label)
	}
	return htmlText(node)
}

// assertAccessiblePage is a small, dependency-free audit of the rules that
// axe reports as serious or critical for this markup: document language,
// a level-one heading, labelled form controls, named buttons and links,
// unique IDs, alert semantics for errors, labelled table cells, and no
// inline script or style that the CSP would block.
func assertAccessiblePage(t *testing.T, page, body string) *html.Node {
	t.Helper()
	document := htmlDocument(t, body)
	root := htmlElements(document, htmlTag("html"))
	if len(root) != 1 {
		t.Fatalf("%s: expected one html element", page)
	}
	if lang, _ := htmlAttr(root[0], "lang"); lang == "" {
		t.Fatalf("%s: html element has no lang", page)
	}
	if titles := htmlElements(document, htmlTag("title")); len(titles) != 1 || htmlText(titles[0]) == "" {
		t.Fatalf("%s: page needs one non-empty title", page)
	}
	if headings := htmlElements(document, htmlTag("h1")); len(headings) != 1 {
		t.Fatalf("%s: expected exactly one h1, got %d", page, len(headings))
	}
	if len(htmlElements(document, htmlTag("main"))) != 1 {
		t.Fatalf("%s: expected one main landmark", page)
	}
	ids := map[string]bool{}
	for _, node := range htmlElements(document, func(*html.Node) bool { return true }) {
		if id, ok := htmlAttr(node, "id"); ok {
			if ids[id] {
				t.Fatalf("%s: duplicate id %q", page, id)
			}
			ids[id] = true
		}
		if _, ok := htmlAttr(node, "style"); ok {
			t.Fatalf("%s: inline style attribute on <%s>", page, node.Data)
		}
		if node.Data == "script" || node.Data == "style" {
			t.Fatalf("%s: inline <%s> element is blocked by the CSP", page, node.Data)
		}
	}
	labelsFor := map[string]bool{}
	for _, label := range htmlElements(document, htmlTag("label")) {
		if target, ok := htmlAttr(label, "for"); ok {
			if !ids[target] {
				t.Fatalf("%s: label for=%q does not match a control", page, target)
			}
			labelsFor[target] = true
		}
	}
	for _, control := range htmlElements(document, func(node *html.Node) bool {
		return node.Data == "input" || node.Data == "select" || node.Data == "textarea"
	}) {
		if kind, _ := htmlAttr(control, "type"); kind == "hidden" || kind == "submit" {
			continue
		}
		id, _ := htmlAttr(control, "id")
		if htmlAncestor(control, "label") == nil && !labelsFor[id] && accessibleName(control) == "" {
			name, _ := htmlAttr(control, "name")
			t.Fatalf("%s: form control %q has no label", page, name)
		}
		if kind, _ := htmlAttr(control, "type"); kind == "password" {
			if autocomplete, _ := htmlAttr(control, "autocomplete"); autocomplete != "current-password" && autocomplete != "new-password" {
				name, _ := htmlAttr(control, "name")
				t.Fatalf("%s: password field %q has autocomplete=%q", page, name, autocomplete)
			}
		}
	}
	for _, control := range htmlElements(document, func(node *html.Node) bool { return node.Data == "button" || node.Data == "a" || node.Data == "summary" }) {
		if accessibleName(control) == "" {
			t.Fatalf("%s: <%s> has no accessible name", page, control.Data)
		}
	}
	for _, alert := range htmlElements(document, func(node *html.Node) bool { return htmlHasClass(node, "error") }) {
		if role, _ := htmlAttr(alert, "role"); role != "alert" {
			t.Fatalf("%s: error message %q is not role=alert", page, htmlText(alert))
		}
	}
	for _, table := range htmlElements(document, htmlTag("table")) {
		for _, header := range htmlElements(table, htmlTag("th")) {
			if scope, _ := htmlAttr(header, "scope"); scope != "col" && scope != "row" {
				t.Fatalf("%s: table header %q has no scope", page, htmlText(header))
			}
		}
		for _, cell := range htmlElements(table, func(node *html.Node) bool {
			if node.Data == "td" {
				return true
			}
			scope, _ := htmlAttr(node, "scope")
			return node.Data == "th" && scope == "row"
		}) {
			if label, _ := htmlAttr(cell, "data-label"); label == "" {
				t.Fatalf("%s: table cell %q has no data-label for the stacked mobile layout", page, htmlText(cell))
			}
		}
	}
	return document
}

func accessibilityFixtures() map[string]pageData {
	now := time.Now().UTC()
	earlier := now.Add(-3 * time.Minute)
	return map[string]pageData{
		"setup": {Error: "Passwords do not match.", Challenge: "challenge"},
		"login": {Error: "Invalid password.", Challenge: "challenge"},
		"reset": {Error: "The reset token is invalid or expired.", Challenge: "challenge"},
		"status": {CSRF: "csrf", Status: store.Status{
			Configured: true, BaselineAt: &earlier, BaselineReady: true,
			ResourceCounts: map[string]int{"devices": 2},
			Collectors: []store.CollectorState{
				{Name: "devices", Supported: true, Baseline: true, PollDurationMS: 12, LastSuccess: &earlier, NextPoll: &now},
				{Name: "dns", Supported: true, FailureCount: 4, LastError: "request failed"},
			},
		}, ExpiryHorizonDays: 14, Expiring: []expiringResource{
			{Kind: "Device node key", Name: "server", Tags: "tag:server", Expires: now.Add(48 * time.Hour), DaysLeft: 2},
			{Kind: "Auth key", Name: "ci enrolment", Expires: now.Add(96 * time.Hour), DaysLeft: 4},
		}},
		"history": {CSRF: "csrf", HistoryCollectors: []string{"devices"}, HistoryEventTypes: []string{"changed"}, HistorySeverities: []string{"high", "medium", "low"}, HistoryFilter: store.HistoryFilter{BatchID: 7, Severity: "high"}, History: store.HistoryPage{
			HasNext: true,
			Batches: []store.HistoryBatch{{ID: 7, ObservedAt: earlier, ChangeCount: 1, Events: []store.HistoryEvent{{
				Collector: "devices", EventType: "changed", ResourceID: "node-1", Name: "laptop", Severity: "high", Muted: true,
				Fields: []store.HistoryFieldChange{{Field: "tags", Old: `["tag:a"]`, New: `["tag:b"]`, HasOld: true, HasNew: true}, {Field: "routes", New: `[]`, HasNew: true}},
			}}}},
		}, HistoryNextURL: "/history?cursor=7", HistoryExportURL: "/history/export"},
		"settings": {CSRF: "csrf", Configured: true, Error: "Notification destination could not be updated.", Message: "Notification test sent.",
			Collectors: []string{"devices", "keys"}, HistoryEventTypes: []string{"created", "changed", "removed"},
			MuteRules:    []store.MuteRule{{ID: 1, Kind: "field", Value: "devices.clientVersion"}, {ID: 2, Kind: "tag", Value: "tag:ci"}},
			Destinations: []destinationPage{{ID: 1, Name: "Primary", DisplayURL: "generic://one", Enabled: true, MinSeverity: "high", ChangeKinds: map[string]bool{"created": true}, RoutingSummary: "severity high or higher", EffectiveFormat: "markdown"}, {ID: 2, Name: "Backup", DisplayURL: "generic://two", Format: "plain", EffectiveFormat: "plain"}}},
	}
}

func TestPagesShareAccessibleLayout(t *testing.T) {
	server, _, _ := testServer(t)
	for page, data := range accessibilityFixtures() {
		response := httptest.NewRecorder()
		server.render(response, page, data)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", page, response.Code)
		}
		document := assertAccessiblePage(t, page, response.Body.String())
		headers := htmlElements(document, func(node *html.Node) bool { return node.Data == "header" && htmlHasClass(node, "site-header") })
		if len(headers) != 1 || !strings.Contains(htmlText(headers[0]), "Version test") {
			t.Fatalf("%s: shared header with version missing", page)
		}
		navs := htmlElements(document, htmlTag("nav"))
		authenticated := page == "status" || page == "history" || page == "settings"
		primary := htmlElements(document, func(node *html.Node) bool {
			label, _ := htmlAttr(node, "aria-label")
			return node.Data == "nav" && label == "Primary"
		})
		if authenticated != (len(primary) == 1) {
			t.Fatalf("%s: primary navigation present=%d, want authenticated=%v (navs=%d)", page, len(primary), authenticated, len(navs))
		}
		if !authenticated {
			continue
		}
		current := htmlElements(primary[0], func(node *html.Node) bool {
			value, _ := htmlAttr(node, "aria-current")
			return node.Data == "a" && value == "page"
		})
		if len(current) != 1 {
			t.Fatalf("%s: expected one aria-current link, got %d", page, len(current))
		}
		if href, _ := htmlAttr(current[0], "href"); href != "/"+page {
			t.Fatalf("%s: aria-current marks %q", page, href)
		}
		logout := htmlElements(primary[0], func(node *html.Node) bool {
			action, _ := htmlAttr(node, "action")
			return node.Data == "form" && action == "/logout"
		})
		if len(logout) != 1 {
			t.Fatalf("%s: logout form missing from shared navigation", page)
		}
	}
}

func TestCollectorTableLabelsEveryValueOnMobile(t *testing.T) {
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.render(response, "status", accessibilityFixtures()["status"])
	document := htmlDocument(t, response.Body.String())
	tables := htmlElements(document, func(node *html.Node) bool { return node.Data == "table" && htmlHasClass(node, "collector-table") })
	if len(tables) != 1 {
		t.Fatalf("collector state must be a real table, got %d tables", len(tables))
	}
	var columns []string
	for _, header := range htmlElements(htmlElements(tables[0], htmlTag("thead"))[0], htmlTag("th")) {
		columns = append(columns, htmlText(header))
	}
	rows := htmlElements(htmlElements(tables[0], htmlTag("tbody"))[0], htmlTag("tr"))
	if len(rows) != 2 {
		t.Fatalf("collector rows=%d", len(rows))
	}
	for _, row := range rows {
		var labels []string
		for cell := row.FirstChild; cell != nil; cell = cell.NextSibling {
			if cell.Type != html.ElementNode {
				continue
			}
			label, _ := htmlAttr(cell, "data-label")
			labels = append(labels, label)
		}
		if strings.Join(labels, "|") != strings.Join(columns, "|") {
			t.Fatalf("row labels %v do not match column headers %v", labels, columns)
		}
	}
}

func TestHistoryDiffIsUnderstandableWithoutColour(t *testing.T) {
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.render(response, "history", accessibilityFixtures()["history"])
	document := htmlDocument(t, response.Body.String())
	diffs := htmlElements(document, func(node *html.Node) bool { return node.Data == "table" && htmlHasClass(node, "field-diff") })
	if len(diffs) != 1 {
		t.Fatalf("field diff must be a table, got %d", len(diffs))
	}
	rows := htmlElements(htmlElements(diffs[0], htmlTag("tbody"))[0], htmlTag("tr"))
	if len(rows) != 2 {
		t.Fatalf("diff rows=%d", len(rows))
	}
	for _, row := range rows {
		cells := htmlElements(row, htmlTag("td"))
		if len(cells) != 2 {
			t.Fatalf("diff row has %d value cells", len(cells))
		}
		if text := htmlText(cells[0]); !strings.HasPrefix(text, "Old") {
			t.Fatalf("previous value lacks a text marker: %q", text)
		}
		if text := htmlText(cells[1]); !strings.HasPrefix(text, "New") {
			t.Fatalf("current value lacks a text marker: %q", text)
		}
	}
	if text := htmlText(htmlElements(rows[1], htmlTag("td"))[0]); !strings.Contains(text, "(absent)") {
		t.Fatalf("absent previous value must be spelled out, got %q", text)
	}
}

func TestDestinationButtonsHaveDistinctAccessibleNames(t *testing.T) {
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.render(response, "settings", accessibilityFixtures()["settings"])
	document := htmlDocument(t, response.Body.String())
	names := map[string]bool{}
	for _, button := range htmlElements(document, func(node *html.Node) bool {
		return node.Data == "button" && htmlAncestor(node, "article") != nil
	}) {
		name := accessibleName(button)
		if names[name] {
			t.Fatalf("destination button name %q is repeated", name)
		}
		names[name] = true
	}
	for _, want := range []string{"Disable Primary", "Enable Backup", "Send test to Primary", "Remove Backup"} {
		if !names[want] {
			t.Fatalf("missing destination button name %q in %v", want, names)
		}
	}
	success := htmlElements(document, func(node *html.Node) bool { return htmlHasClass(node, "success") })
	if len(success) != 1 {
		t.Fatal("success message missing")
	}
	if role, _ := htmlAttr(success[0], "role"); role != "status" {
		t.Fatalf("success message role=%q", role)
	}
}

func TestTemplatesAreReadableAndStylesSupportBothThemes(t *testing.T) {
	entries, err := fs.Glob(assets, "templates/*.html")
	if err != nil || len(entries) != 7 {
		t.Fatalf("templates=%v err=%v", entries, err)
	}
	for _, name := range entries {
		content, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(content), "\n") {
			if len(line) > 400 {
				t.Fatalf("%s:%d is %d characters; keep templates formatted for review", name, number+1, len(line))
			}
		}
		if name != "templates/layout.html" && strings.Contains(string(content), "<header") {
			t.Fatalf("%s duplicates the shared header", name)
		}
	}
	css, err := fs.ReadFile(assets, "static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	style := string(css)
	if !strings.Contains(style, "@media (prefers-color-scheme: light)") || strings.Contains(style, "color-scheme: light dark;") {
		t.Fatal("stylesheet must ship a light palette instead of claiming light support it does not style")
	}
	if strings.Contains(style, " height: 64px") || !strings.Contains(style, "flex-wrap: wrap") {
		t.Fatal("header must wrap instead of using a fixed height")
	}
	if !strings.Contains(style, "content: attr(data-label)") {
		t.Fatal("stacked mobile tables must show data-label column names")
	}
}
