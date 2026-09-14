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
	// SubnetMap statically maps scanned subnets onto NetBox prefixes and VLANs.
	// It is the only source of that mapping: nothing is looked up in NetBox and
	// nothing is inferred. An empty subnet_map leaves the policy behaving
	// exactly as it did before the key existed.
	SubnetMap []SubnetMapEntry `yaml:"subnet_map,omitempty"`
}

// PrefixDefaults holds NetBox defaults applied to the prefixes declared in
// scope.subnet_map. Every field is optional, and an unset field is left off the
// emitted entity rather than defaulted: Diode omits absent optional fields from
// the changeset, so NetBox keeps whatever the prefix already carries. Defaulting
// status here would make every scan re-assert it over an operator-set value.
//
// Field names mirror gnmi-discovery's PrefixDefaults so policy YAML stays
// portable between the two backends; status, is_pool and mark_utilized are
// additions, because network-discovery declares its prefixes rather than
// deriving them from discovered addresses.
type PrefixDefaults struct {
	Status       string   `yaml:"status,omitempty"`
	Role         string   `yaml:"role,omitempty"`
	Tenant       string   `yaml:"tenant,omitempty"`
	IsPool       *bool    `yaml:"is_pool,omitempty"`
	MarkUtilized *bool    `yaml:"mark_utilized,omitempty"`
	Tags         []string `yaml:"tags,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

// VlanDefaults holds NetBox defaults applied to the VLANs declared in
// scope.subnet_map. Optional in the same sense as PrefixDefaults.
type VlanDefaults struct {
	Group       VlanGroupParameters `yaml:"group,omitempty"`
	Status      string              `yaml:"status,omitempty"`
	Role        string              `yaml:"role,omitempty"`
	Tenant      string              `yaml:"tenant,omitempty"`
	Tags        []string            `yaml:"tags,omitempty"`
	Description string              `yaml:"description,omitempty"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Vrf         string   `yaml:"vrf,omitempty"`
	Rd          string   `yaml:"rd,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Site        string   `yaml:"site,omitempty"`
	Role        string   `yaml:"role,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	NetworkMask *int     `yaml:"network_mask,omitempty"`
	// Prefix and Vlan apply only to entities declared in scope.subnet_map. With
	// no subnet_map the backend emits IP addresses alone, exactly as it did
	// before these blocks existed, and both are ignored.
	Prefix PrefixDefaults `yaml:"prefix,omitempty"`
	Vlan   VlanDefaults   `yaml:"vlan,omitempty"`
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule *string  `yaml:"schedule,omitempty"`
	Defaults Defaults `yaml:"defaults"`
	Timeout  int      `yaml:"timeout"`
	// CustomFields are NetBox custom field values applied to every IPAddress and
	// Prefix the policy emits. Keys are NetBox custom field names (snake_case,
	// the name and not the label); the field definitions must already exist in
	// NetBox, as Diode does not create them. Values keep their YAML type, which
	// selects the matching CustomFieldValue variant.
	CustomFields map[string]any `yaml:"custom_fields,omitempty"`
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
