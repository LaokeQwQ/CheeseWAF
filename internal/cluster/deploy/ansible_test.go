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
		{name: "unsafe region", plan: Plan{ClusterID: "cw-test", Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf", Region: "cn-east\nansible_password=pwned"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GenerateAnsiblePackage(tt.plan); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAnsiblePackageFailsClosedWithoutVerifiedRelease(t *testing.T) {
	pkg, err := GenerateAnsiblePackage(Plan{ClusterID: "cw-test", Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf", Region: "cn-east-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := string(pkg.File("roles/cheesewaf/tasks/main.yml"))
	for _, want := range []string{"cheesewaf_binary_sha256", "ansible.builtin.get_url", "ansible.builtin.systemd_service", "/health/ready"} {
		if !strings.Contains(tasks, want) {
			t.Fatalf("generated tasks missing %q", want)
		}
	}
	if strings.Contains(tasks, "Show next manual step") {
		t.Fatal("package must not claim deployment while deferring installation to a manual step")
	}
}

func TestAnsibleReleaseAssertionPrecedesEveryRemoteChange(t *testing.T) {
	pkg, err := GenerateAnsiblePackage(Plan{ClusterID: "cw-test", Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf"}}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := string(pkg.File("roles/cheesewaf/tasks/main.yml"))
	assertAt := strings.Index(tasks, "- name: Require a verified CheeseWAF release source")
	blockAt := strings.Index(tasks, "- name: Deploy CheeseWAF transactionally")
	if assertAt < 0 || blockAt < 0 || assertAt > blockAt {
		t.Fatalf("release assertion must precede the deployment block: assert=%d block=%d", assertAt, blockAt)
	}
	for _, mutation := range []string{"ansible.builtin.file:", "ansible.builtin.copy:", "ansible.builtin.template:", "ansible.builtin.get_url:", "ansible.builtin.command:", "ansible.builtin.systemd_service:", "ansible.builtin.user:"} {
		if strings.Contains(tasks[:assertAt], mutation) {
			t.Fatalf("remote mutation %q appears before release assertion", mutation)
		}
	}
}

func TestAnsibleDeploymentHasTransactionalRollbackAndCleanup(t *testing.T) {
	pkg, err := GenerateAnsiblePackage(Plan{ClusterID: "cw-test", Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf"}}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := string(pkg.File("roles/cheesewaf/tasks/main.yml"))
	assertInOrder(t, tasks, "block:", "Create execution-specific backup directory", "Probe existing CheeseWAF files", "Capture CheeseWAF enabled state", "Capture CheeseWAF active state", "Back up existing CheeseWAF files", "Download verified CheeseWAF binary", "Activate verified CheeseWAF binary atomically", "Reload systemd after deployment", "Start CheeseWAF service", "Verify CheeseWAF readiness", "Clean execution-specific backup after successful deployment", "rescue:", "Restore files that existed before deployment", "Remove files created by failed deployment", "Reload systemd after rollback", "Restore CheeseWAF enable state", "Restore CheeseWAF running state", "Fail deployment after rollback", "always:", "Clean deployment staging directory")
	for _, want := range []string{"ansible.builtin.tempfile:", "state: directory", "ansible.builtin.stat:", "remote_src: true", "argv:", "cheesewaf_pre_enabled.rc == 0", "cheesewaf_pre_active.rc == 0", "when: item.stat.exists", "when: not item.stat.exists"} {
		if !strings.Contains(tasks, want) {
			t.Fatalf("generated tasks missing rollback detail %q", want)
		}
	}
	if strings.Contains(tasks, "ansible.builtin.shell:") {
		t.Fatal("deployment must not use shell commands")
	}
	rescueAt := strings.Index(tasks, "  rescue:")
	alwaysAt := strings.Index(tasks, "  always:")
	if rescueAt < 0 || alwaysAt < 0 || strings.Contains(tasks[rescueAt:], "Clean execution-specific backup directory") {
		t.Fatal("failed deployment must retain its execution backup for recovery")
	}
}

func assertInOrder(t *testing.T, text string, parts ...string) {
	t.Helper()
	position := 0
	for _, part := range parts {
		next := strings.Index(text[position:], part)
		if next < 0 {
			t.Fatalf("expected %q after byte %d", part, position)
		}
		position += next + len(part)
	}
}
