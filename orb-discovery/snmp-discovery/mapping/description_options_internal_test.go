package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func deviceDescriptionValues() (map[ObjectIDIndex]*ObjectIDValue, *Entry) {
	values := map[ObjectIDIndex]*ObjectIDValue{
		"1.3.6.1.2.1.1.5.0": {OID: "1.3.6.1.2.1.1.5.0", Parent: "1.3.6.1.2.1.1.5", Value: "router-a", Type: OctetString},
		"1.3.6.1.2.1.1.1.0": {OID: "1.3.6.1.2.1.1.1.0", Parent: "1.3.6.1.2.1.1.1", Value: "Vendor OS 1.0", Type: OctetString},
	}
	entry := &Entry{
		OID: "1.3.6.1.2.1.1", Entity: "device", Field: "_id",
		MappingEntries: []Entry{
			{OID: "1.3.6.1.2.1.1.5", Entity: "device", Field: "name"},
			{OID: "1.3.6.1.2.1.1.1", Entity: "device", Field: "description"},
		},
	}
	return values, entry
}

func TestDeviceDescriptionFromSysDescrOption(t *testing.T) {
	logger := slog.Default()
	off := false

	cases := []struct {
		name    string
		options config.Options
		want    *string
	}{
		{"unset keeps legacy behaviour", config.Options{}, StringPtr("Vendor OS 1.0")},
		{"false leaves description off", config.Options{DeviceDescriptionFromSysDescr: &off}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapper := &DeviceMapper{logger: logger, skipDescription: !tc.options.DeviceDescriptionEnabled()}
			values, entry := deviceDescriptionValues()
			entity := mapper.Map(values, entry, NewEntityRegistry(logger), &config.Defaults{})
			device, ok := entity.(*diode.Device)
			require.True(t, ok)
			assert.Equal(t, tc.want, device.Description)
		})
	}
}

func TestInterfaceDescriptionFromIfAliasOption(t *testing.T) {
	logger := slog.Default()
	off := false
	values := map[ObjectIDIndex]*ObjectIDValue{
		"1.3.6.1.2.1.2.2.1.1.1":     {OID: "1.3.6.1.2.1.2.2.1.1.1", Index: "1", Parent: "1.3.6.1.2.1.2.2.1.1", Value: "1", Type: Integer},
		"1.3.6.1.2.1.2.2.1.2.1":     {OID: "1.3.6.1.2.1.2.2.1.2.1", Index: "1", Parent: "1.3.6.1.2.1.2.2.1.2", Value: "eth0", Type: OctetString},
		"1.3.6.1.2.1.31.1.1.1.18.1": {OID: "1.3.6.1.2.1.31.1.1.1.18.1", Index: "1", Parent: "1.3.6.1.2.1.31.1.1.1.18", Value: "uplink", Type: OctetString},
	}
	entry := &Entry{
		OID: "1.3.6.1.2.1.2.2.1.1", Entity: "interface", Field: "_id",
		MappingEntries: []Entry{
			{OID: "1.3.6.1.2.1.2.2.1.1", Entity: "interface", Field: "_id"},
			{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			{OID: "1.3.6.1.2.1.31.1.1.1.18", Entity: "interface", Field: "description"},
		},
	}
	for _, tc := range []struct {
		name    string
		options config.Options
		want    *string
	}{
		{"unset keeps legacy behaviour", config.Options{}, StringPtr("uplink")},
		{"false leaves description off", config.Options{InterfaceDescriptionFromIfAlias: &off}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapper, err := NewInterfaceMapper(logger, nil, config.InterfaceNameSourceAuto)
			require.NoError(t, err)
			mapper.skipDescription = !tc.options.InterfaceDescriptionEnabled()
			entity := mapper.Map(values, entry, NewEntityRegistry(logger), nil)
			iface, ok := entity.(*diode.Interface)
			require.True(t, ok)
			assert.Equal(t, tc.want, iface.Description)
		})
	}
}
