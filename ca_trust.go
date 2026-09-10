package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func trustMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, "ca-trusted")
}

type caFamily struct {
	ID         string
	CertPath   string
	Refresh    []string // command argv
	Hint       string
}

func detectCAFamily() caFamily {
	id, like := osRelease()
	has := func(bin string) bool {
		_, err := exec.LookPath(bin)
		return err == nil
	}
	deb := caFamily{
		ID:       "debian",
		CertPath: "/usr/local/share/ca-certificates/skytap.crt",
		Refresh:  []string{"update-ca-certificates"},
		Hint:     "Debian/Ubuntu/Alpine: copy PEM to /usr/local/share/ca-certificates/skytap.crt then run update-ca-certificates",
	}
	rhel := caFamily{
		ID:       "rhel",
		CertPath: "/etc/pki/ca-trust/source/anchors/skytap.crt",
		Refresh:  []string{"update-ca-trust", "extract"},
		Hint:     "Alma/Rocky/RHEL/Fedora: copy PEM to /etc/pki/ca-trust/source/anchors/skytap.crt then run update-ca-trust extract",
	}
	arch := caFamily{
		ID:       "arch",
		CertPath: "/etc/ca-certificates/trust-source/anchors/skytap.crt",
		Refresh:  []string{"update-ca-trust"},
		Hint:     "Arch/BlackArch: copy PEM to /etc/ca-certificates/trust-source/anchors/skytap.crt then run update-ca-trust",
	}

	blob := id + " " + like
	switch {
	case strings.Contains(blob, "arch") || strings.Contains(blob, "blackarch") || strings.Contains(blob, "manjaro") || strings.Contains(blob, "artix"):
		return arch
	case strings.Contains(blob, "rhel") || strings.Contains(blob, "fedora") || strings.Contains(blob, "centos") ||
		strings.Contains(blob, "almalinux") || strings.Contains(blob, "rocky") || strings.Contains(blob, "ol"):
		return rhel
	case strings.Contains(blob, "debian") || strings.Contains(blob, "ubuntu") || strings.Contains(blob, "alpine"):
		return deb
	}
	if has("update-ca-trust") && dirOK("/etc/pki/ca-trust/source/anchors") {
		return rhel
	}
	if has("update-ca-trust") && dirOK("/etc/ca-certificates/trust-source/anchors") {
		return arch
	}
	return deb
}

func dirOK(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func osRelease() (id, like string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "ID_LIKE":
			like = strings.ToLower(v)
		}
	}
	return id, like
}

func caInstalledAt(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), "BEGIN CERTIFICATE") && len(b) > 50
}

func caStatus(pem []byte, dataDir string) map[string]any {
	fp := ""
	if len(pem) > 0 {
		sum := sha256.Sum256(pem)
		fp = hex.EncodeToString(sum[:])
	}
	fam := detectCAFamily()
	onDisk := runtime.GOOS == "linux" && caInstalledAt(fam.CertPath)
	wanted, _ := os.ReadFile(trustMarkerPath(dataDir))
	wantTrust := strings.TrimSpace(string(wanted)) == "1"
	id, _ := osRelease()
	return map[string]any{
		"os":          runtime.GOOS,
		"distro":      id,
		"family":      fam.ID,
		"fingerprint": fp,
		"installed":   onDisk,
		"want_trust":  wantTrust,
		"trust_path":  fam.CertPath,
		"note":        "Clients that you INTERCEPT or MOCK must trust this CA. OBSERVED needs none. Trust is per machine / container / VM — not inherited from the host.",
		"install_hint": fam.Hint,
		"can_install": runtime.GOOS == "linux" && os.Getuid() == 0,
	}
}

func installCATrust(pem []byte, dataDir string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("CA auto-install is Linux-only")
	}
	fam := detectCAFamily()
	if err := os.MkdirAll(filepath.Dir(fam.CertPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(fam.CertPath, pem, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	_ = os.WriteFile(trustMarkerPath(dataDir), []byte("1\n"), 0o644)
	if len(fam.Refresh) == 0 {
		return nil
	}
	cmd := exec.Command(fam.Refresh[0], fam.Refresh[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(fam.Refresh, " "), err, out)
	}
	return nil
}

func restoreCATrust(pem []byte, dataDir string) {
	b, err := os.ReadFile(trustMarkerPath(dataDir))
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		return
	}
	_ = installCATrust(pem, dataDir)
}
