package deploy

import (
	"strings"
	"testing"
)

func TestGenerateAnsiblePackageIncludesInventoryAndNoSecrets(t *testing.T) {
	pkg, err := GenerateAnsiblePackage(Plan{
		ClusterID: "cw-test",
		Channel:   "canary",
		Nodes: []Host{
			{Name: "waf-a", Address: "10.0.0.1", Role: "waf", SSHPort: 22},
			{Name: "monitor-a", Address: "10.0.0.2", Role: "monitor", SSHPort: 22},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"inventory.ini",
		"group_vars/all.yml",
		"playbook.yml",
		"roles/cheesewaf/tasks/main.yml",
		"roles/cheesewaf/templates/cheesewaf.yaml.j2",
		"README.md",
	} {
		if len(pkg.File(name)) == 0 {
			t.Fatalf("package missing %s", name)
		}
	}
	if !strings.Contains(string(pkg.File("inventory.ini")), "waf-a") {
		t.Fatal("inventory missing WAF host")
	}
	if !strings.Contains(string(pkg.File("inventory.ini")), "[monitor]") {
		t.Fatal("inventory missing monitor group")
	}
	for name, data := range pkg.Files() {
		if name == "README.md" {
			continue
		}
		contents := strings.ToLower(string(data))
		if strings.Contains(contents, "ansible_password") ||
			strings.Contains(contents, "ansible_ssh_private_key_file") ||
			strings.Contains(contents, "private_key:") ||
			strings.Contains(contents, "password:") {
			t.Fatalf("%s must not contain raw credential fields", name)
		}
	}
}

func TestGenerateAnsiblePackageRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
	}{
		{name: "missing cluster id", plan: Plan{Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf"}}}},
		{name: "missing nodes", plan: Plan{ClusterID: "cw-test"}},
		{name: "bad role", plan: Plan{ClusterID: "cw-test", Nodes: []Host{{Name: "db-a", Address: "10.0.0.1", Role: "db"}}}},
		{name: "bad channel", plan: Plan{ClusterID: "cw-test", Channel: "stable; rm -rf /", Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GenerateAnsiblePackage(tt.plan); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
