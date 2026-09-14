package config_test

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// The unknown-key warning pass must stay silent on a policy that uses the full
// new surface: it re-decodes strictly, so a new key it does not know about
// would produce a warning on a correct file and train operators to ignore it.
func TestWarnUnknownPolicyKeysSilentOnNewKeys(t *testing.T) {
	data, err := os.ReadFile("testdata/full_policy.yaml")
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	config.WarnUnknownPolicyKeys(data, slog.New(slog.NewTextHandler(buf, nil)))
	assert.Empty(t, buf.String())
}
