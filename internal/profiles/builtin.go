package profiles

// Builtin returns the target-runtime policy compiled into flow. release
// manifests are checked against this independent local graph before any
// artifact is downloaded or executed. keep the repository JSON declarations
// in sync; TestBuiltinMatchesRepository enforces exact semantic equality.
func Builtin() (*Registry, error) {
	return NewRegistry([]Profile{
		{SchemaVersion: SchemaVersion, Name: "ssh", Description: "Hardened public-key-only SSH baseline", Installable: true, Components: []string{"ssh"}},
		{SchemaVersion: SchemaVersion, Name: "ssh-gui", Description: "Locked malwarelab desktop with loopback-only VNC", Installable: true, DependsOn: []string{"ssh"}, ConflictsWith: []string{"decepticon", "examstation"}, Components: []string{"ssh"}},
		{SchemaVersion: SchemaVersion, Name: "vpn", Description: "General Mullvad VPN mode with the normal Firefox workflow", Installable: true, DependsOn: []string{"ssh"}, ConflictsWith: []string{"examstation", "vpn-pbp-de"}, Components: []string{"vpn"}},
		{SchemaVersion: SchemaVersion, Name: "vpn-pbp-de", Description: "PBP-only Mullvad Germany mode with Shadowsocks 443 and lockdown", Internal: true, DependsOn: []string{"ssh-gui"}, ConflictsWith: []string{"decepticon", "examstation", "vpn"}, Components: []string{"vpn"}},
		{SchemaVersion: SchemaVersion, Name: "pbp", Description: "Persistent Camoufox browser persona protected by the PBP VPN mode", Installable: true, DependsOn: []string{"vpn-pbp-de"}, ConflictsWith: []string{"decepticon", "examstation"}, Components: []string{"pbp"}},
		{SchemaVersion: SchemaVersion, Name: "decepticon", Description: "In development: external Decepticon integration; source not shipped", DependsOn: []string{"ssh"}, ConflictsWith: []string{"examstation", "pbp", "ssh-gui", "vpn-pbp-de"}, Components: []string{"vpn", "decepticon"}},
		{SchemaVersion: SchemaVersion, Name: "examstation", Description: "In development: managed exam station integration; source not shipped", DependsOn: []string{"ssh"}, ConflictsWith: []string{"decepticon", "pbp", "ssh-gui", "vpn", "vpn-pbp-de"}, Components: []string{"examstation"}},
	})
}
