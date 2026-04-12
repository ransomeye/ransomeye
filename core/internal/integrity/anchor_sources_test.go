package integrity

import (
	"strings"
	"testing"
)

func TestCpuIdentityFromCPUinfo_serial(t *testing.T) {
	content := `
processor	: 0
Serial		: deadbeef
model name	: Fake CPU
`
	id, err := cpuIdentityFromCPUinfo(content)
	if err != nil {
		t.Fatal(err)
	}
	if id != "deadbeef" {
		t.Fatalf("want serial, got %q", id)
	}
}

func TestCpuIdentityFromCPUinfo_modelName(t *testing.T) {
	content := `
processor	: 0
model name	: Intel  X
`
	id, err := cpuIdentityFromCPUinfo(content)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(id, "Intel") {
		t.Fatalf("want model name, got %q", id)
	}
}

func TestCpuIdentityFromCPUinfo_vendorTuple(t *testing.T) {
	content := `
processor	: 0
vendor_id	: Foo
cpu family	: 6
model		: 42
`
	id, err := cpuIdentityFromCPUinfo(content)
	if err != nil {
		t.Fatal(err)
	}
	if id != "Foo|6|42" {
		t.Fatalf("want tuple, got %q", id)
	}
}

func TestFirstCPUinfoBlock_secondProcessorStops(t *testing.T) {
	content := `
processor	: 0
model name	: A
processor	: 1
model name	: B
`
	m := firstCPUinfoBlock(content)
	if m == nil || m["model name"] != "A" {
		t.Fatalf("want first CPU only, got %v", m)
	}
}
