package netboxsync

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ShiftCron returns a five-field cron expression that fires delayMinutes after
// expr does.
//
// Supported: a minute field that is a single number, and any hour field made
// of numbers, ranges, steps and lists ("*", "*/6", "1-5", "0,12", "8-18/2").
// When the shift carries an hour past midnight the day fields must all be "*",
// since moving a firing to the next day would otherwise change which days it
// runs on. Anything else returns an error; set an explicit schedule instead.
func ShiftCron(expr string, delayMinutes int) (string, error) {
	if delayMinutes < 0 {
		return "", fmt.Errorf("cannot shift %q by a negative delay", expr)
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return "", fmt.Errorf("cron %q: only five-field expressions can be shifted", expr)
	}
	if delayMinutes == 0 {
		return strings.Join(fields, " "), nil
	}
	minute, err := strconv.Atoi(fields[0])
	if err != nil || minute < 0 || minute > 59 {
		return "", fmt.Errorf("cron %q: the minute field must be a single number to be shifted", expr)
	}
	total := minute + delayMinutes
	fields[0] = strconv.Itoa(total % 60)
	carry := total / 60
	if carry == 0 {
		return strings.Join(fields, " "), nil
	}
	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return "", fmt.Errorf("cron %q: hour field: %w", expr, err)
	}
	daysRestricted := fields[2] != "*" || fields[3] != "*" || fields[4] != "*"
	shifted := make(map[int]bool, len(hours))
	for _, h := range hours {
		next := h + carry
		if next >= 24 && daysRestricted {
			return "", fmt.Errorf("cron %q: shifting by %d minutes moves a run to another day while the day fields are restricted", expr, delayMinutes)
		}
		shifted[next%24] = true
	}
	if len(shifted) == 24 {
		fields[1] = "*"
	} else {
		list := make([]int, 0, len(shifted))
		for h := range shifted {
			list = append(list, h)
		}
		sort.Ints(list)
		parts := make([]string, len(list))
		for i, h := range list {
			parts[i] = strconv.Itoa(h)
		}
		fields[1] = strings.Join(parts, ",")
	}
	return strings.Join(fields, " "), nil
}

// parseCronField expands one cron field into its values.
func parseCronField(field string, lo, hi int) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(field, ",") {
		step := 1
		if base, s, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid step in %q", part)
			}
			step = n
			part = base
		}
		start, end := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			x, err1 := strconv.Atoi(a)
			y, err2 := strconv.Atoi(b)
			if err1 != nil || err2 != nil || x > y {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			start, end = x, y
		default:
			x, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			start = x
			if step == 1 {
				end = x
			}
		}
		if start < lo || end > hi {
			return nil, fmt.Errorf("%q is out of range %d-%d", part, lo, hi)
		}
		for v := start; v <= end; v += step {
			seen[v] = true
		}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}
