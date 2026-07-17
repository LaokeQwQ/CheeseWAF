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

- name: Render CheeseWAF cluster config
  ansible.builtin.template:
    src: cheesewaf.yaml.j2
    dest: "{{ cheesewaf_config_dir }}/cheesewaf.yaml"
    owner: "{{ cheesewaf_service_user }}"
    group: "{{ cheesewaf_service_user }}"
    mode: "0640"

- name: Show next manual step
  ansible.builtin.debug:
    msg: "Install or update the cheesewaf binary, then run the node join flow generated by the controller."
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
