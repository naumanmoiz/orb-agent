package config

import "time"

// Hostname represents a hostname associated with a host
type Hostname struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Port represents a network port
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

// ExtraPort represents additional port information
type ExtraPort struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// HostMetadata represents the metadata of a host
type HostMetadata struct {
	Hostnames  []Hostname  `json:"hostnames"`
	Ports      []Port      `json:"ports"`
	ExtraPorts []ExtraPort `json:"extra_ports"`
}

// Status represents the status of the network-discovery service
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Scope represents the scope of a policy
type Scope struct {
	Targets        []string `yaml:"targets"`
	Ports          []string `yaml:"ports,omitempty"`
	ExcludePorts   []string `yaml:"exclude_ports,omitempty"`
	Timing         *int     `yaml:"timing,omitempty"`
	FastMode       *bool    `yaml:"fast_mode,omitempty"`
	PingScan       *bool    `yaml:"ping_scan,omitempty"`
	TopPorts       *int     `yaml:"top_ports,omitempty"`
	ScanTypes      []string `yaml:"scan_types,omitempty"`
	MaxRetries     *int     `yaml:"max_retries,omitempty"`
	DNSServers     []string `yaml:"dns_servers,omitempty"`
	OSDetection    *bool    `yaml:"os_detection,omitempty"`
	UseTargetMasks *bool    `yaml:"use_target_masks,omitempty"`
	ICMPEcho       *bool    `yaml:"icmp_echo,omitempty"`
	ICMPTimestamp  *bool    `yaml:"icmp_timestamp,omitempty"`
	ICMPNetMask    *bool    `yaml:"icmp_netmask,omitempty"`
	SkipHost       *bool    `yaml:"skip_host,omitempty"`
	// SubnetMap declares the subnets to create as NetBox prefixes, and gives
	// each discovered address the mask of the most specific entry containing it.
	// Nothing is looked up in NetBox and nothing is inferred. An empty
	// subnet_map leaves the policy emitting IP addresses alone, as before.
	SubnetMap []SubnetMapEntry `yaml:"subnet_map,omitempty"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Vrf         string   `yaml:"vrf,omitempty"`
	Rd          string   `yaml:"rd,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Role        string   `yaml:"role,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	NetworkMask *int     `yaml:"network_mask,omitempty"`
	// Prefix applies only to the prefixes declared in scope.subnet_map. With no
	// subnet_map the backend emits IP addresses alone and this is ignored.
	Prefix PrefixDefaults `yaml:"prefix,omitempty"`
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule *string  `yaml:"schedule,omitempty"`
	Defaults Defaults `yaml:"defaults"`
	Timeout  int      `yaml:"timeout"`
	// CustomFields are NetBox custom field values applied to every IP address
	// the policy emits. Keys are NetBox custom field names (snake_case, the name
	// and not the label); the definitions must already exist in NetBox, as Diode
	// does not create them. Values keep their YAML type, which selects the
	// matching CustomFieldValue variant.
	CustomFields map[string]any `yaml:"custom_fields,omitempty"`
	// TimestampPrecision truncates the ${SCAN_TIMESTAMP} token. A timestamp that
	// changes on every run makes every entity differ from what NetBox holds, so
	// the reconciler rewrites all of them on every scan. See ResolvedTimestampPrecision.
	TimestampPrecision string `yaml:"timestamp_precision,omitempty"`
}

// ResolvedTimestampPrecision returns the configured ${SCAN_TIMESTAMP} precision,
// defaulting to "day".
//
// The default is deliberately coarse. At nanosecond precision every entity in
// every run carries a value NetBox has never seen, so the reconciler writes all
// of them and NetBox records a changelog entry for each. Truncating to the day
// keeps "when was this last seen" useful while letting an otherwise unchanged
// address reconcile to a no-op.
func (c PolicyConfig) ResolvedTimestampPrecision() string {
	if c.TimestampPrecision == "" {
		return PrecisionDay
	}
	return c.TimestampPrecision
}

// Policy represents a network-discovery policy
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}

// Policies represents a collection of network-discovery policies
type Policies struct {
	Policies map[string]Policy `mapstructure:"policies"`
}
