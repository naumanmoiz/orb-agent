package netboxsync

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShiftCron(t *testing.T) {
	for _, tc := range []struct {
		in    string
		delay int
		want  string
	}{
		{"0 */6 * * *", 30, "30 */6 * * *"},
		{"0 */6 * * *", 0, "0 */6 * * *"},
		{"45 */6 * * *", 30, "15 1,7,13,19 * * *"},
		{"0 */6 * * *", 90, "30 1,7,13,19 * * *"},
		{"0 * * * *", 75, "15 * * * *"},
		{"30 23 * * *", 45, "15 0 * * *"},
		{"0 8-18/2 * * 1-5", 30, "30 8-18/2 * * 1-5"},
		{"50 8-18/2 * * 1-5", 30, "20 9,11,13,15,17,19 * * 1-5"},
		{"15 0,12 * * *", 24 * 60, "15 0,12 * * *"},
	} {
		got, err := ShiftCron(tc.in, tc.delay)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got, "%s + %d", tc.in, tc.delay)
	}
}

func TestShiftCronRejects(t *testing.T) {
	for _, tc := range []struct {
		in    string
		delay int
	}{
		{"*/5 * * * *", 30},
		{"0,30 * * * *", 10},
		{"@hourly", 10},
		{"0 0 * * * *", 10},
		{"30 23 * * 1", 45}, // would move Monday's run to Tuesday
		{"0 * * * *", -1},
	} {
		_, err := ShiftCron(tc.in, tc.delay)
		assert.Error(t, err, tc.in)
	}
}
