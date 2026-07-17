package deploy

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Role    string `json:"role"`
	SSHPort int    `json:"ssh_port"`
	Region  string `json:"region,omitempty"`
}

type Plan struct {
	ClusterID string `json:"cluster_id"`
	Channel   string `json:"channel"`
	Nodes     []Host `json:"nodes"`
}

type Package struct {
	files map[string][]byte
}

func (p Package) File(name string) []byte {
	if p.files == nil {
		return nil
	}
	return bytes.Clone(p.files[name])
}

func (p Package) Files() map[string][]byte {
	out := make(map[string][]byte, len(p.files))
	for name, data := range p.files {
		out[name] = bytes.Clone(data)
	}
	return out
}

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var safeRegion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

func GenerateAnsiblePackage(plan Plan) (Package, error) {
	normalized, err := normalizePlan(plan)
	if err != nil {
		return Package{}, err
	}
	files := map[string][]byte{}
	for _, item := range []struct {
		name string
		body func() (string, error)
	}{
		{"inventory.ini", func() (string, error) { return inventory(normalized), nil }},
		{"group_vars/all.yml", func() (string, error) { return groupVars(normalized) }},
		{"playbook.yml", func() (string, error) { return playbook(), nil }},
		{"roles/cheesewaf/tasks/main.yml", func() (string, error) { return tasks(), nil }},
		{"roles/cheesewaf/templates/cheesewaf.yaml.j2", func() (string, error) { return configTemplate(), nil }},
		{"README.md", func() (string, error) { return packageReadme(), nil }},
	} {
		body, err := item.body()
		if err != nil {
			return Package{}, err
		}
		files[item.name] = []byte(body)
	}
	return Package{files: files}, nil
}

func normalizePlan(plan Plan) (Plan, error) {
	plan.ClusterID = strings.TrimSpace(plan.ClusterID)
	if !safeIdentifier.MatchString(plan.ClusterID) {
		return Plan{}, fmt.Errorf("cluster_id must be a safe identifier")
	}
	if plan.Channel == "" {
		plan.Channel = "canary"
	}
	switch plan.Channel {
	case "dev", "canary", "stable":
	default:
		return Plan{}, fmt.Errorf("channel must be dev, canary, or stable")
	}
	if len(plan.Nodes) == 0 {
		return Plan{}, fmt.Errorf("at least one node is required")
	}
	seen := map[string]struct{}{}
	for i := range plan.Nodes {
		node := &plan.Nodes[i]
		node.Name = strings.TrimSpace(node.Name)
		node.Address = strings.TrimSpace(node.Address)
		node.Role = strings.TrimSpace(node.Role)
		node.Region = strings.TrimSpace(node.Region)
		if !safeIdentifier.MatchString(node.Name) {
			return Plan{}, fmt.Errorf("node name %q is not a safe identifier", node.Name)
		}
		if _, ok := seen[node.Name]; ok {
			return Plan{}, fmt.Errorf("duplicate node name %q", node.Name)
		}
		seen[node.Name] = struct{}{}
		if err := validateHostAddress(node.Address); err != nil {
			return Plan{}, fmt.Errorf("node %q address invalid: %w", node.Name, err)
		}
		switch node.Role {
		case "waf", "monitor":
		default:
			return Plan{}, fmt.Errorf("node %q role must be waf or monitor", node.Name)
		}
		if node.SSHPort == 0 {
			node.SSHPort = 22
		}
		if node.SSHPort < 1 || node.SSHPort > 65535 {
			return Plan{}, fmt.Errorf("node %q ssh_port must be between 1 and 65535", node.Name)
		}
		if node.Region != "" && !safeRegion.MatchString(node.Region) {
			return Plan{}, fmt.Errorf("node %q region must be 1-32 letters, numbers, dots, underscores, or hyphens", node.Name)
		}
	}
	sort.SliceStable(plan.Nodes, func(i, j int) bool {
		if plan.Nodes[i].Role == plan.Nodes[j].Role {
			return plan.Nodes[i].Name < plan.Nodes[j].Name
		}
		return plan.Nodes[i].Role > plan.Nodes[j].Role
	})
	return plan, nil
}

func validateHostAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address is required")
	}
	if strings.ContainsAny(address, " \t\r\n;&|`$<>") {
		return fmt.Errorf("address contains unsafe characters")
	}
	if ip := net.ParseIP(address); ip != nil {
		return nil
	}
	if strings.Contains(address, "/") {
		return fmt.Errorf("address must be a host or IP, not a path")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(address) {
		return fmt.Errorf("address contains unsupported characters")
	}
	return nil
}

func inventory(plan Plan) string {
	var b strings.Builder
	writeGroup := func(role string) {
		fmt.Fprintf(&b, "[%s]\n", role)
		for _, node := range plan.Nodes {
			if node.Role != role {
				continue
			}
			fmt.Fprintf(&b, "%s ansible_host=%s ansible_port=%d cheesewaf_role=%s", node.Name, node.Address, node.SSHPort, node.Role)
			if node.Region != "" {
				fmt.Fprintf(&b, " cheesewaf_region=%s", node.Region)
			}
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	writeGroup("waf")
	writeGroup("monitor")
	b.WriteString("[cheesewaf:children]\nwaf\nmonitor\n")
	return b.String()
}

func groupVars(plan Plan) (string, error) {
	return renderTemplate("group_vars", `---
cheesewaf_cluster_id: "{{ .ClusterID }}"
cheesewaf_release_channel: "{{ .Channel }}"
# Release channel labels: dev=开发版, canary=预览版, stable=正式版.
cheesewaf_binary_url: ""
cheesewaf_binary_sha256: ""
cheesewaf_install_dir: "/opt/cheesewaf"
cheesewaf_config_dir: "/etc/cheesewaf"
cheesewaf_data_dir: "/var/lib/cheesewaf"
cheesewaf_service_user: "cheesewaf"
cheesewaf_interconnect_port: 9444
cheesewaf_join_requires_approval: true
`, plan)
}

func playbook() string {
	return `---
- name: Deploy CheeseWAF cluster nodes
  hosts: cheesewaf
  become: true
  roles:
    - cheesewaf
`
}

func tasks() string {
	return `---
- name: Require a verified CheeseWAF release source
  ansible.builtin.assert:
    that:
      - cheesewaf_binary_url | length > 0
      - cheesewaf_binary_sha256 | length == 64
      - cheesewaf_binary_sha256 is match('^[A-Fa-f0-9]{64}$')
    fail_msg: "A verified CheeseWAF binary URL and SHA-256 are required; deployment was not performed."

- name: Deploy CheeseWAF transactionally
  block:
    - name: Create execution-specific backup directory
      ansible.builtin.tempfile:
        state: directory
        prefix: cheesewaf-backup-
      register: cheesewaf_backup_dir

    - name: Create execution-specific staging directory
      ansible.builtin.tempfile:
        state: directory
        prefix: cheesewaf-staging-
      register: cheesewaf_staging_dir

    - name: Probe existing CheeseWAF files
      ansible.builtin.stat:
        path: "{{ item.path }}"
      loop:
        - { name: binary, path: "{{ cheesewaf_install_dir }}/cheesewaf" }
        - { name: config, path: "{{ cheesewaf_config_dir }}/cheesewaf.yaml" }
        - { name: unit, path: /etc/systemd/system/cheesewaf.service }
      register: cheesewaf_original_files

    - name: Capture CheeseWAF enabled state
      ansible.builtin.command:
        argv: [systemctl, is-enabled, cheesewaf.service]
      register: cheesewaf_pre_enabled
      changed_when: false
      failed_when: false

    - name: Capture CheeseWAF active state
      ansible.builtin.command:
        argv: [systemctl, is-active, cheesewaf.service]
      register: cheesewaf_pre_active
      changed_when: false
      failed_when: false

    - name: Back up existing CheeseWAF files
      ansible.builtin.copy:
        src: "{{ item.item.path }}"
        dest: "{{ cheesewaf_backup_dir.path }}/{{ item.item.name }}"
        remote_src: true
        mode: preserve
      loop: "{{ cheesewaf_original_files.results }}"
      when: item.stat.exists

    - name: Create CheeseWAF service user
      ansible.builtin.user:
        name: "{{ cheesewaf_service_user }}"
        system: true
        create_home: false

    - name: Create CheeseWAF directories
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        owner: "{{ cheesewaf_service_user }}"
        group: "{{ cheesewaf_service_user }}"
        mode: "0750"
      loop:
        - "{{ cheesewaf_install_dir }}"
        - "{{ cheesewaf_config_dir }}"
        - "{{ cheesewaf_data_dir }}"

    - name: Download verified CheeseWAF binary
      ansible.builtin.get_url:
        url: "{{ cheesewaf_binary_url }}"
        dest: "{{ cheesewaf_staging_dir.path }}/cheesewaf"
        checksum: "sha256:{{ cheesewaf_binary_sha256 }}"
        mode: "0755"

    - name: Stage CheeseWAF binary on target filesystem
      ansible.builtin.copy:
        src: "{{ cheesewaf_staging_dir.path }}/cheesewaf"
        dest: "{{ cheesewaf_install_dir }}/.cheesewaf.new"
        remote_src: true
        owner: root
        group: root
        mode: "0755"

    - name: Render CheeseWAF cluster config for atomic activation
      ansible.builtin.template:
        src: cheesewaf.yaml.j2
        dest: "{{ cheesewaf_config_dir }}/.cheesewaf.yaml.new"
        owner: "{{ cheesewaf_service_user }}"
        group: "{{ cheesewaf_service_user }}"
        mode: "0640"

    - name: Stage CheeseWAF systemd unit
      ansible.builtin.copy:
        dest: /etc/systemd/system/.cheesewaf.service.new
        mode: "0644"
        content: |
          [Unit]
          Description=CheeseWAF
          After=network-online.target
          Wants=network-online.target
          [Service]
          User={{ cheesewaf_service_user }}
          Group={{ cheesewaf_service_user }}
          ExecStart={{ cheesewaf_install_dir }}/cheesewaf --config {{ cheesewaf_config_dir }}/cheesewaf.yaml
          Restart=on-failure
          NoNewPrivileges=true
          [Install]
          WantedBy=multi-user.target

    - name: Activate verified CheeseWAF binary atomically
      ansible.builtin.command:
        argv: [mv, "{{ cheesewaf_install_dir }}/.cheesewaf.new", "{{ cheesewaf_install_dir }}/cheesewaf"]
      changed_when: true

    - name: Activate CheeseWAF config atomically
      ansible.builtin.command:
        argv: [mv, "{{ cheesewaf_config_dir }}/.cheesewaf.yaml.new", "{{ cheesewaf_config_dir }}/cheesewaf.yaml"]
      changed_when: true

    - name: Activate CheeseWAF systemd unit atomically
      ansible.builtin.command:
        argv: [mv, /etc/systemd/system/.cheesewaf.service.new, /etc/systemd/system/cheesewaf.service]
      changed_when: true

    - name: Reload systemd after deployment
      ansible.builtin.systemd_service:
        daemon_reload: true

    - name: Start CheeseWAF service
      ansible.builtin.systemd_service:
        name: cheesewaf
        enabled: true
        state: restarted

    - name: Verify CheeseWAF readiness
      ansible.builtin.uri:
        url: "https://127.0.0.1:9443/health/ready"
        method: GET
        validate_certs: false
        status_code: 200
      register: cheesewaf_readiness
      retries: 12
      delay: 5
      until: cheesewaf_readiness.status == 200

    - name: Clean execution-specific backup after successful deployment
      ansible.builtin.file:
        path: "{{ cheesewaf_backup_dir.path }}"
        state: absent

  rescue:
    - name: Stop service created by failed deployment
      ansible.builtin.systemd_service:
        name: cheesewaf
        state: stopped
      failed_when: false
      when: not (cheesewaf_original_files.results[2].stat.exists | default(false))

    - name: Restore files that existed before deployment
      ansible.builtin.copy:
        src: "{{ cheesewaf_backup_dir.path }}/{{ item.item.name }}"
        dest: "{{ item.item.path }}"
        remote_src: true
        mode: preserve
      loop: "{{ cheesewaf_original_files.results }}"
      when: item.stat.exists

    - name: Remove files created by failed deployment
      ansible.builtin.file:
        path: "{{ item.item.path }}"
        state: absent
      loop: "{{ cheesewaf_original_files.results }}"
      when: not item.stat.exists

    - name: Remove partially staged activation files
      ansible.builtin.file:
        path: "{{ item }}"
        state: absent
      loop:
        - "{{ cheesewaf_install_dir }}/.cheesewaf.new"
        - "{{ cheesewaf_config_dir }}/.cheesewaf.yaml.new"
        - /etc/systemd/system/.cheesewaf.service.new

    - name: Reload systemd after rollback
      ansible.builtin.systemd_service:
        daemon_reload: true

    - name: Restore CheeseWAF enable state
      ansible.builtin.systemd_service:
        name: cheesewaf
        enabled: "{{ cheesewaf_pre_enabled.rc == 0 }}"
      when: cheesewaf_original_files.results[2].stat.exists

    - name: Restore CheeseWAF running state
      ansible.builtin.systemd_service:
        name: cheesewaf
        state: "{{ 'started' if cheesewaf_pre_active.rc == 0 else 'stopped' }}"
      when: cheesewaf_original_files.results[2].stat.exists

    - name: Fail deployment after rollback
      ansible.builtin.fail:
        msg: "CheeseWAF deployment failed. Rollback was attempted; the execution backup remains at {{ cheesewaf_backup_dir.path }} for recovery verification."

  always:
    - name: Clean deployment staging directory
      ansible.builtin.file:
        path: "{{ cheesewaf_staging_dir.path }}"
        state: absent
      when: cheesewaf_staging_dir.path is defined

`
}

func configTemplate() string {
	return `deployment:
  mode: cluster
cluster:
  enabled: true
  cluster_id: "{{ cheesewaf_cluster_id }}"
  node_id: "{{ inventory_hostname }}"
  ha_mode: "{% if groups['waf'] | length >= 3 %}multi-node-ha{% elif groups['waf'] | length >= 2 and groups['monitor'] | length >= 1 %}minimum-ha{% elif groups['waf'] | length >= 2 %}dual-node-load-balancing{% else %}single-node{% endif %}"
  interconnect:
    listen: "0.0.0.0:{{ cheesewaf_interconnect_port }}"
    advertise_addr: "{{ ansible_host }}:{{ cheesewaf_interconnect_port }}"
    mtls_required: true
  consensus:
    provider: builtin
  join:
    require_approval: "{{ cheesewaf_join_requires_approval }}"
    token_ttl: 15m
  nodes:
{% for host in groups['cheesewaf'] %}
    - id: "{{ host }}"
      role: "{{ hostvars[host].cheesewaf_role }}"
      advertise_addr: "{{ hostvars[host].ansible_host }}:{{ cheesewaf_interconnect_port }}"
{% endfor %}
`
}

func packageReadme() string {
	return `# CheeseWAF Cluster Ansible Package

This package is generated by CheeseWAF M2 deployment tooling.

It contains no SSH passwords, private keys, API tokens, or join tokens. Provide SSH credentials through your own Ansible inventory, SSH agent, or CI secret store.

Generated files:

- ` + "`inventory.ini`" + `
- ` + "`group_vars/all.yml`" + `
- ` + "`playbook.yml`" + `
- ` + "`roles/cheesewaf/tasks/main.yml`" + `
- ` + "`roles/cheesewaf/templates/cheesewaf.yaml.j2`" + `

Run:

` + "```bash" + `
ansible-playbook -i inventory.ini playbook.yml
` + "```" + `

Two WAF nodes are deployed as load balancing, not full high availability. Minimum HA requires two WAF nodes plus one monitor node. Multi-node HA requires three or more WAF nodes and the later majority-confirmation runtime.
`
}

func renderTemplate(name, body string, data any) (string, error) {
	tpl, err := template.New(name).Parse(body)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := tpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
