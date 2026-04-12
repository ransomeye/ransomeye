// Phase 7.0: multi-source root-of-trust material (offline, fail-closed).
package integrity

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const procCPUInfo = "/proc/cpuinfo"

// anchorPreimage returns normalized lines: machine-id + "\n" + cpu-id + "\n" + rootfs-uuid (all lowercase, trimmed).
// Any missing or empty component is an error (no fallback).
func anchorPreimage() (string, error) {
	mid, err := readNormalizedMachineID()
	if err != nil {
		return "", err
	}
	cpu, err := readNormalizedCPUIdentity()
	if err != nil {
		return "", err
	}
	uuid, err := readNormalizedRootFSUUID()
	if err != nil {
		return "", err
	}
	if mid == "" || cpu == "" || uuid == "" {
		return "", fmt.Errorf("integrity: anchor material: empty component")
	}
	return mid + "\n" + cpu + "\n" + uuid, nil
}

func normalizeAnchorComponent(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func readNormalizedMachineID() (string, error) {
	b, err := os.ReadFile(MachineIDPath)
	if err != nil {
		return "", fmt.Errorf("integrity: machine-id: %w", err)
	}
	s := normalizeAnchorComponent(string(b))
	if s == "" {
		return "", fmt.Errorf("integrity: machine-id empty")
	}
	return s, nil
}

func readNormalizedCPUIdentity() (string, error) {
	b, err := os.ReadFile(procCPUInfo)
	if err != nil {
		return "", fmt.Errorf("integrity: cpuinfo: %w", err)
	}
	id, err := cpuIdentityFromCPUinfo(string(b))
	if err != nil {
		return "", err
	}
	s := normalizeAnchorComponent(id)
	if s == "" {
		return "", fmt.Errorf("integrity: cpu identity empty")
	}
	return s, nil
}

func cpuIdentityFromCPUinfo(content string) (string, error) {
	block := firstCPUinfoBlock(content)
	if block == nil {
		return "", fmt.Errorf("integrity: cpuinfo: no processor block")
	}
	if v := block["serial"]; v != "" {
		return v, nil
	}
	if v := block["model name"]; v != "" {
		return v, nil
	}
	// Tuple: vendor_id, cpu family, model, model name — stable join.
	var parts []string
	for _, k := range []string{"vendor_id", "cpu family", "model", "model name"} {
		if v := block[k]; v != "" {
			parts = append(parts, strings.TrimSpace(v))
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("integrity: cpuinfo: no serial, model name, or vendor tuple")
	}
	return strings.Join(parts, "|"), nil
}

func firstCPUinfoBlock(content string) map[string]string {
	sc := bufio.NewScanner(strings.NewReader(content))
	m := make(map[string]string)
	sawProcessorLine := false
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if len(m) > 0 {
				break
			}
			continue
		}
		k, v, ok := parseCPUinfoKV(line)
		if !ok {
			continue
		}
		if k == "processor" {
			if sawProcessorLine && len(m) > 0 {
				break
			}
			sawProcessorLine = true
			continue
		}
		if sawProcessorLine {
			m[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func parseCPUinfoKV(line string) (key, val string, ok bool) {
	idx := strings.IndexRune(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:idx]))
	val = strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func readNormalizedRootFSUUID() (string, error) {
	u, err := rootFSUUID()
	if err != nil {
		return "", err
	}
	s := normalizeAnchorComponent(u)
	if s == "" {
		return "", fmt.Errorf("integrity: root filesystem UUID empty")
	}
	return s, nil
}

func rootFSUUID() (string, error) {
	out, err := exec.Command("findmnt", "-n", "-o", "UUID", "/").Output()
	u := strings.TrimSpace(string(out))
	if err == nil {
		nu := normalizeAnchorComponent(u)
		if nu != "" && nu != "unknown" {
			return u, nil
		}
	}
	out2, err2 := exec.Command("findmnt", "-n", "-o", "SOURCE", "/").Output()
	if err2 != nil {
		return rootFSUUIDFromProcMounts()
	}
	src := strings.TrimSpace(string(out2))
	if uuid := uuidFromMountSource(src); uuid != "" {
		return uuid, nil
	}
	if u, err3 := rootFSUUIDFromProcMounts(); err3 == nil {
		return u, nil
	} else {
		_ = err3
	}
	return "", fmt.Errorf("integrity: root filesystem UUID unavailable (findmnt SOURCE=%q)", src)
}

func uuidFromMountSource(src string) string {
	src = strings.TrimSpace(src)
	lower := strings.ToLower(src)
	if strings.HasPrefix(lower, "uuid=") {
		return strings.TrimSpace(src[len("uuid="):])
	}
	out, err := exec.Command("blkid", "-o", "value", "-s", "UUID", src).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func rootFSUUIDFromProcMounts() (string, error) {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("integrity: read /proc/mounts: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		dev, mp, ok := splitProcMountsRootLine(line)
		if !ok || mp != "/" {
			continue
		}
		if uuid := uuidFromMountSource(dev); uuid != "" {
			return uuid, nil
		}
	}
	return "", fmt.Errorf("integrity: root filesystem UUID unavailable from /proc/mounts")
}

func splitProcMountsRootLine(line string) (dev, mp string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", "", false
	}
	if fields[1] == "/" {
		return fields[0], "/", true
	}
	return "", "", false
}
