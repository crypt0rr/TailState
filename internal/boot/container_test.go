package boot

import (
	"os"
	"strings"
	"testing"
)

func TestLoadParsesContainerMode(t *testing.T) {
	t.Setenv("TAILSTATE_LISTEN_ADDR", "0.0.0.0:8080")
	t.Setenv("TAILSTATE_CONTAINER", "1")
	config, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if !config.Container || !config.ContainerWildcardListener() {
		t.Fatalf("container mode not detected: %#v", config)
	}
	t.Setenv("TAILSTATE_CONTAINER", "maybe")
	if _, err := Load("test"); err == nil {
		t.Fatal("invalid TAILSTATE_CONTAINER was accepted")
	}
}

// TestContainerImageAndComposeDeclareContainerMode keeps the image and the
// default Compose file in sync with the diagnostics that rely on them.
func TestContainerImageAndComposeDeclareContainerMode(t *testing.T) {
	for _, path := range []string{"../../Dockerfile", "../../compose.yaml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "TAILSTATE_CONTAINER") {
			t.Fatalf("%s does not set TAILSTATE_CONTAINER", path)
		}
	}
}
