package store

import "strconv"

// Encryption bindings name the storage location of every value sealed with
// the master key. They are authenticated as AES-GCM additional data in the v2
// envelope, so a ciphertext copied to another row or column (for example one
// destination's URL onto another destination, or the evidence signing key
// into a destination) fails to decrypt instead of being silently accepted.
// The strings are part of the on-disk format and must never change.

const masterKeyCheckMeta = "master_key_check"

func settingsBinding(column string) string { return "settings." + column + ":1" }

func destinationBinding(id int64) string {
	return "notification_destinations.service_url_enc:" + strconv.FormatInt(id, 10)
}

func metaBinding(key string) string { return "meta.value:" + key }
