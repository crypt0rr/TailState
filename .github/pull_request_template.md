## Summary

<!-- What changes and why. Link the issue: "Fixes #123". -->

## Checklist

- [ ] `gofmt`, `go vet ./...`, `go test -race ./...`, and `bash scripts/invariant-suite.sh` pass
- [ ] Behaviour changes have a regression test (and an entry in `.github/invariant-tests.txt` for security, drift, delivery, persistence, or evidence guarantees)
- [ ] README/CONTRIBUTING updated where behaviour or operations change
- [ ] No credentials, database files, backups, or local Compose state are included
