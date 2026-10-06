package config

// ContextKey represents the key for the context
type ContextKey string

// PolicyPayload represents the payload for the agent policy
type PolicyPayload struct {
	Action       string `json:"action"`
	ID           string `json:"id"`
	DatasetID    string `json:"dataset_id"`
	AgentGroupID string `json:"agent_group_id"`
	Name         string `json:"name"`
	Backend      string `json:"backend"`
	Format       string `json:"format"`
	Version      int32  `json:"version"`
	Data         any    `json:"data"`
}

// LocalManager represents the local ConfigManager configuration.
type LocalManager struct {
	Config string `yaml:"config"`
}

// GitHubAppAuth holds GitHub App installation credentials for the Git
// ConfigManager. Only github.com is supported (including GitHub Enterprise
// Cloud, which is served from github.com / api.github.com).
type GitHubAppAuth struct {
	// ClientID is the JWT issuer. Prefer the app's Client ID (Iv23li...), which is
	// what the GitHub API documentation now specifies; the numeric App ID from
	// the app's settings page is still accepted, but is the legacy form and may
	// be dropped in a future API version.
	ClientID string `yaml:"client_id"`
	// InstallationID identifies the installation of the app on the account that
	// owns the repository. It is the numeric id in the URL of the installation's
	// settings page - not the App ID.
	InstallationID string `yaml:"installation_id"`
	// PrivateKey is the path to the app's .pem private key, or the PEM document
	// itself when injected by ${VAR} or a secrets manager.
	PrivateKey string `yaml:"private_key"`
}

// GitManager represents the Git ConfigManager configuration.
type GitManager struct {
	URL        string        `yaml:"url"`
	Branch     string        `yaml:"branch"`
	Auth       string        `yaml:"auth"`
	Schedule   *string       `yaml:"schedule,omitempty"`
	Username   string        `yaml:"username"`
	Password   string        `yaml:"password"`
	PrivateKey string        `yaml:"private_key"`
	SkipTLS    bool          `yaml:"skip_tls"`
	GitHubApp  GitHubAppAuth `yaml:"github_app"`
}

// FleetManager represents the Fleet ConfigManager configuration.
type FleetManager struct {
	URL                      string `yaml:"url"`
	TokenURL                 string `yaml:"token_url"`
	Timeout                  *int   `yaml:"timeout,omitempty"`
	SkipTLS                  bool   `yaml:"skip_tls"`
	ClientID                 string `yaml:"client_id"`
	ClientSecret             string `yaml:"client_secret"`
	TokenExpiryCheckInterval *int   `yaml:"token_expiry_check_interval,omitempty"` // Check interval in seconds (default: 30)
	TokenReconnectBuffer     *int   `yaml:"token_reconnect_buffer,omitempty"`      // Reconnect buffer in seconds before expiry (default: 120)
	OTLPBridgeGRPCPort       *int   `yaml:"otlp_bridge_grpc_port,omitempty"`       // GRPC port for the OTLP bridge (default: 4317)
	OTLPBridgeHTTPPort       *int   `yaml:"otlp_bridge_http_port,omitempty"`       // HTTP port for the OTLP bridge (default: 4318)
	OTLPBridgeBindHost       string `yaml:"otlp_bridge_bind_host,omitempty"`       // Host both bridge listeners bind to (default: localhost; set 0.0.0.0 or :: to expose them)
}

// NetBoxManager represents the NetBox ConfigManager configuration. It reads
// IPAM prefixes from NetBox and generates network_discovery (and optionally
// snmp_discovery) policies from them. See docs/NETBOX_PREFIX_SYNC.md.
type NetBoxManager struct {
	// URL is the NetBox base URL, e.g. https://netbox.example.com. ${VAR} is
	// resolved from the environment.
	URL string `yaml:"url"`
	// Token is the API token: "Token <t>", "Bearer <t>", or a bare token
	// (nbt_ v2 tokens are sent as Bearer, others as Token). ${VAR} is resolved
	// from the environment.
	Token         string `yaml:"token"`
	SkipTLSVerify bool   `yaml:"skip_tls_verify"`
	// Schedule is the cron expression on which NetBox is re-read. Unset means
	// the policies are generated once at startup.
	Schedule *string `yaml:"schedule,omitempty"`
	// Timeout is the per-request HTTP timeout in seconds (default 30).
	Timeout *int `yaml:"timeout,omitempty"`
	// Retries is how many times a failed request is retried (default 3).
	Retries *int `yaml:"retries,omitempty"`
	// PageSize is the page size used against the NetBox API (default 1000).
	PageSize int `yaml:"page_size,omitempty"`
	// Statuses are the prefix statuses eligible for scanning (default
	// [container, active]). Prefixes of every status are still fetched, since
	// all of them count when computing what a parent's children cover.
	Statuses []string `yaml:"statuses,omitempty"`
	// Filters are extra query parameters passed to /api/ipam/prefixes/.
	Filters map[string]any `yaml:"filters,omitempty"`
	// GeneratedConfigPath, when set, receives the rendered policies on every
	// refresh, before they are applied.
	GeneratedConfigPath string `yaml:"generated_config_path,omitempty"`
	// AllowEmpty lets a refresh that finds no prefixes at all remove every
	// generated policy. Off by default, so a NetBox outage or a wrong filter
	// cannot wipe the running set.
	AllowEmpty bool `yaml:"allow_empty,omitempty"`

	NetworkDiscovery NetBoxNetworkDiscovery `yaml:"network_discovery"`
	SNMPDiscovery    NetBoxSNMPDiscovery    `yaml:"snmp_discovery"`
}

// NetBoxNetworkDiscovery configures the network_discovery policies the NetBox
// ConfigManager generates.
type NetBoxNetworkDiscovery struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule,omitempty"`
	// StragglerDelayMinutes shifts Schedule to produce the straggler schedule.
	StragglerDelayMinutes *int `yaml:"straggler_delay_minutes,omitempty"`
	// StragglerSchedule replaces the shifted schedule outright.
	StragglerSchedule string `yaml:"straggler_schedule,omitempty"`
	// StaggerMinutes spreads the generated policies' start times evenly over
	// this many minutes so they do not all fire at once.
	StaggerMinutes int `yaml:"stagger_minutes,omitempty"`
	// Timeout is the policy timeout in minutes.
	Timeout             int  `yaml:"timeout,omitempty"`
	MaxTargetsPerPolicy int  `yaml:"max_targets_per_policy,omitempty"`
	MaxHostsPerPolicy   int  `yaml:"max_hosts_per_policy,omitempty"`
	MaxBlockPrefixLenV4 *int `yaml:"max_block_prefix_len_v4,omitempty"`
	MaxBlockPrefixLenV6 *int `yaml:"max_block_prefix_len_v6,omitempty"`
	// Config is merged into every generated policy's config block.
	Config map[string]any `yaml:"config,omitempty"`
	// Scope is merged into every generated policy's scope block.
	Scope     map[string]any  `yaml:"scope,omitempty"`
	Straggler NetBoxStraggler `yaml:"straggler"`
}

// NetBoxStraggler configures the second pass, which scans the part of every
// parent prefix that none of its children covers.
type NetBoxStraggler struct {
	Enabled             *bool          `yaml:"enabled,omitempty"`
	MaxBlockPrefixLenV4 *int           `yaml:"max_block_prefix_len_v4,omitempty"`
	MaxBlockPrefixLenV6 *int           `yaml:"max_block_prefix_len_v6,omitempty"`
	MaxHostsPerParent   int            `yaml:"max_hosts_per_parent,omitempty"`
	PingOnly            *bool          `yaml:"ping_only,omitempty"`
	MaxTargetsPerPolicy int            `yaml:"max_targets_per_policy,omitempty"`
	MaxHostsPerPolicy   int            `yaml:"max_hosts_per_policy,omitempty"`
	Scope               map[string]any `yaml:"scope,omitempty"`
}

// NetBoxSNMPDiscovery configures the snmp_discovery policies the NetBox
// ConfigManager generates.
type NetBoxSNMPDiscovery struct {
	Enabled             bool           `yaml:"enabled"`
	Schedule            string         `yaml:"schedule,omitempty"`
	StaggerMinutes      int            `yaml:"stagger_minutes,omitempty"`
	IncludeStragglers   bool           `yaml:"include_stragglers,omitempty"`
	MaxTargetsPerPolicy int            `yaml:"max_targets_per_policy,omitempty"`
	MaxHostsPerPolicy   int            `yaml:"max_hosts_per_policy,omitempty"`
	Authentication      map[string]any `yaml:"authentication,omitempty"`
	Config              map[string]any `yaml:"config,omitempty"`
}

// Sources represents the configuration for manager sources, including cloud, local, git and netbox.
type Sources struct {
	Local  LocalManager  `yaml:"local"`
	Git    GitManager    `yaml:"git"`
	Fleet  FleetManager  `yaml:"fleet"`
	NetBox NetBoxManager `yaml:"netbox"`
}

// ManagerConfig represents the configuration for the Config Manager
type ManagerConfig struct {
	Active  string  `yaml:"active"`
	Sources Sources `yaml:"sources"`
}

// VaultManager represents the configuration for the Vault manager
type VaultManager struct {
	Auth      string         `yaml:"auth"`
	AuthArgs  map[string]any `yaml:"auth_args"`
	Address   string         `yaml:"address"`
	Namespace string         `yaml:"namespace"`
	Mount     string         `yaml:"mount,omitempty"`
	Timeout   *int           `yaml:"timeout,omitempty"`
	Schedule  *string        `yaml:"schedule,omitempty"`
}

// FleetSecretsManager represents the configuration for the Fleet secrets manager
type FleetSecretsManager struct {
	Timeout *int `yaml:"timeout,omitempty"` // Request timeout in seconds
}

// DelineaManager represents the configuration for the Delinea Secret Server manager
type DelineaManager struct {
	ServerURL string  `yaml:"server_url"`
	Tenant    string  `yaml:"tenant"`
	Username  string  `yaml:"username"`
	Password  string  `yaml:"password"`
	Schedule  *string `yaml:"schedule,omitempty"`
}

// DopplerManager represents the configuration for the Doppler secrets manager
type DopplerManager struct {
	Token    string  `yaml:"token"`
	APIHost  string  `yaml:"api_host,omitempty"`
	Project  string  `yaml:"project,omitempty"`
	Config   string  `yaml:"config,omitempty"`
	Timeout  *int    `yaml:"timeout,omitempty"`
	Schedule *string `yaml:"schedule,omitempty"`
}

// CyberArkManager represents the configuration for the CyberArk Central
// Credential Provider (CCP) secrets manager.
type CyberArkManager struct {
	URL           string  `yaml:"url"`
	AppID         string  `yaml:"app_id"`
	Reason        string  `yaml:"reason,omitempty"`
	SkipTLSVerify bool    `yaml:"skip_tls_verify,omitempty"`
	CABundle      string  `yaml:"ca_bundle,omitempty"`
	ClientCert    string  `yaml:"client_cert,omitempty"`
	ClientKey     string  `yaml:"client_key,omitempty"`
	Timeout       *int    `yaml:"timeout,omitempty"`
	Schedule      *string `yaml:"schedule,omitempty"`
}

// DSVManager represents the configuration for the Delinea DevOps Secrets Vault
// (DSV) secrets manager. DSV is a distinct product from Delinea Secret Server
// (see DelineaManager).
type DSVManager struct {
	Tenant       string  `yaml:"tenant"`
	ClientID     string  `yaml:"client_id"`
	ClientSecret string  `yaml:"client_secret"`
	TLD          string  `yaml:"tld,omitempty"`
	URLTemplate  string  `yaml:"url_template,omitempty"`
	Schedule     *string `yaml:"schedule,omitempty"`
}

// SecretsSources represents the configuration for manager sources, including vault, fleet, delinea, doppler, cyberark and dsv.
type SecretsSources struct {
	Vault    VaultManager        `yaml:"vault"`
	Fleet    FleetSecretsManager `yaml:"fleet"`
	Delinea  DelineaManager      `yaml:"delinea"`
	Doppler  DopplerManager      `yaml:"doppler"`
	CyberArk CyberArkManager     `yaml:"cyberark"`
	DSV      DSVManager          `yaml:"dsv"`
}

// ManagerSecrets represents the configuration for the Secrets Manager
type ManagerSecrets struct {
	Active  string         `yaml:"active"`
	Sources SecretsSources `yaml:"sources"`
}

// BackendCommons represents common configuration for backends
type BackendCommons struct {
	Otlp struct {
		Grpc        string            `yaml:"grpc"`
		HTTP        string            `yaml:"http"`
		AgentLabels map[string]string `yaml:"agent_labels"`
	} `yaml:"otlp"`
	Diode struct {
		Target          string `yaml:"target"`
		ClientID        string `yaml:"client_id"`
		ClientSecret    string `yaml:"client_secret"`
		AgentName       string `yaml:"agent_name"`
		DryRun          bool   `yaml:"dry_run"`
		DryRunOutputDir string `yaml:"dry_run_output_dir"`
	}
	Debug bool // Debug flag from CLI (not from YAML config)
}

// FilesManagerConfig configures the FilesManager subsystem.
type FilesManagerConfig struct {
	// Active selects the files-manager source type. "fleet" enables fleet
	// bundle delivery; any other value — including "" and the reserved
	// "local"/"git"/"cron" — currently disables file delivery (no-op manager).
	Active string `yaml:"active"`
	// Root is the directory under which FilesManager stores all managed files.
	// Defaults to /opt/orb/files when unset.
	Root string `yaml:"root"`
	// Sources holds per-source options.
	Sources FilesSources `yaml:"sources"`
}

// FilesSources holds files-manager source configuration.
type FilesSources struct {
	Fleet FleetFilesManager `yaml:"fleet"`
}

// FleetFilesManager holds fleet-files-source options. Reserved for now.
type FleetFilesManager struct{}

// OrbAgent represents the configuration for the Orb agent
type OrbAgent struct {
	Backends       map[string]any     `yaml:"backends"`
	Policies       map[string]any     `yaml:"policies"`
	Labels         map[string]string  `yaml:"labels"`
	ConfigManager  ManagerConfig      `yaml:"config_manager"`
	SecretsManager ManagerSecrets     `yaml:"secrets_manager"`
	FilesManager   FilesManagerConfig `yaml:"files_manager"`
	Debug          struct {
		Enable bool `yaml:"enable"`
	} `yaml:"debug"`
	ConfigFile string `yaml:"config_file"`
}

// Config represents the overall configuration
type Config struct {
	Version  float64  `yaml:"version"`
	OrbAgent OrbAgent `yaml:"orb"`
}
