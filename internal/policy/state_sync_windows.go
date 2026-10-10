package policy

// Windows does not expose directory Sync through os.File. Cooperating readers
// still hold the sidecar lock across the closed-temp-file rename.
func syncBlocklistDirectory(string) error { return nil }
