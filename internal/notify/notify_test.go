package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConvertLegacyMattermostURLs(t *testing.T) {
	native, err := ConvertLegacyMattermostURL("https://mattermost.example/hooks/token")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(native, "mattermost://TailState@mattermost.example/token?") || !strings.Contains(native, "icon=%3Asatellite%3A") {
		t.Fatalf("unexpected native URL: %s", native)
	}

	generic, err := ConvertLegacyMattermostURL("http://mattermost.example/custom/hooks/token")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"generic://mattermost.example/custom/hooks/token", "template=json", "messagekey=text", "%24username=TailState", "%24icon_emoji=%3Asatellite%3A", "disabletls=true"} {
		if !strings.Contains(generic, want) {
			t.Fatalf("generic URL %q does not contain %q", generic, want)
		}
	}
}

func TestValidateAndRedact(t *testing.T) {
	if err := Validate("not-a-shoutrrr-url"); err == nil {
		t.Fatal("expected invalid URL")
	} else if strings.Contains(err.Error(), "not-a-shoutrrr-url") {
		t.Fatalf("validation error echoed URL: %s", err)
	}
	if got := RedactURL("mattermost://TailState:secret@host.example:8443/token?icon=satellite"); got != "mattermost://host.example:8443" {
		t.Fatalf("unexpected redaction: %s", got)
	}
	message := sanitize(`request failed for https://host.example/hooks/super-secret-token`, "mattermost://TailState@host.example/super-secret-token")
	if strings.Contains(message, "super-secret-token") {
		t.Fatalf("token leaked from transformed service URL: %s", message)
	}
	queryMessage := sanitize("upstream rejected token=SUPERSECRET123 for hooks.example.com", "generic://hooks.example.com/post?token=SUPERSECRET123&template=json")
	if strings.Contains(queryMessage, "SUPERSECRET123") {
		t.Fatalf("query credential leaked through sanitization: %s", queryMessage)
	}
}

func TestDestinationURLRedactsEncodedComponents(t *testing.T) {
	encodedQueryMessage := sanitize("provider rejected SUPER%2FSECRET%2B123", "generic://hooks.example.com/post?token=SUPER%2FSECRET%2B123&template=json")
	if strings.Contains(encodedQueryMessage, "SUPER%2FSECRET%2B123") || strings.Contains(encodedQueryMessage, "SUPER/SECRET+123") {
		t.Fatalf("percent-encoded query credential leaked through sanitization: %s", encodedQueryMessage)
	}
	encodedComponentMessage := sanitize(
		"provider rejected /hooks/super%2Fsecret fragment%2Fcredential SECRETKEY=1",
		"generic://hooks.example.com/hooks/super%2Fsecret?SECRETKEY=1#fragment%2Fcredential",
	)
	for _, secret := range []string{"super%2Fsecret", "super/secret", "fragment%2Fcredential", "fragment/credential", "SECRETKEY"} {
		if strings.Contains(encodedComponentMessage, secret) {
			t.Fatalf("encoded URL component %q leaked through sanitization: %s", secret, encodedComponentMessage)
		}
	}
	doubleEncodedMessage := sanitize(
		"provider rejected SECRET/VALUE and /hooks/DOUBLE/PATH",
		"generic://hooks.example.com/hooks/DOUBLE%252FPATH?token=SECRET%252FVALUE",
	)
	for _, secret := range []string{"SECRET/VALUE", "SECRET%2FVALUE", "DOUBLE/PATH", "DOUBLE%2FPATH"} {
		if strings.Contains(doubleEncodedMessage, secret) {
			t.Fatalf("repeatedly encoded URL component %q leaked through sanitization: %s", secret, doubleEncodedMessage)
		}
	}
}

func TestSendGenericWebhook(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serviceURL := strings.Replace(server.URL, "http://", "generic://", 1) + "?disabletls=true&template=json&messagekey=text&%24username=TailState&%24icon_emoji=%3Asatellite%3A"
	if err := New().Send(context.Background(), serviceURL, "hello"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"text":"hello"`, `"username":"TailState"`, `"icon_emoji":":satellite:"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("payload %q missing %q", body, want)
		}
	}
}

func TestSendNativeMattermostWebhook(t *testing.T) {
	var path, body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		defer r.Body.Close()
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	parsed := strings.TrimPrefix(server.URL, "http://")
	serviceURL := "mattermost://TailState@" + parsed + "/token?disabletls=true&icon=%3Asatellite%3A"
	if err := New().Send(context.Background(), serviceURL, "hello"); err != nil {
		t.Fatal(err)
	}
	if path != "/hooks/token" || !strings.Contains(body, `"text":"hello"`) || !strings.Contains(body, `"username":"TailState"`) || !strings.Contains(body, `"icon_emoji":":satellite:"`) {
		t.Fatalf("unexpected Mattermost request path=%q body=%q", path, body)
	}
}

func TestSendDoesNotFollowRedirect(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	serviceURL := strings.Replace(server.URL, "http://", "generic://", 1) + "?disabletls=true"
	if err := New().Send(context.Background(), serviceURL, "hello"); err == nil {
		t.Fatal("expected redirect response to fail")
	}
	if redirected {
		t.Fatal("sender followed redirect")
	}
}
