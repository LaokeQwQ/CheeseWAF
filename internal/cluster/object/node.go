package object

import "time"

type NodeSpec struct {
	Role          string `json:"role" yaml:"role"`
	AdvertiseAddr string `json:"advertise_addr" yaml:"advertise_addr"`
	Region        string `json:"region,omitempty" yaml:"region,omitempty"`
	Datacenter    string `json:"datacenter,omitempty" yaml:"datacenter,omitempty"`
	Weight        int    `json:"weight,omitempty" yaml:"weight,omitempty"`
}

type NodeStatus struct {
	Mode              string    `json:"mode" yaml:"mode"`
	CanReceiveTraffic bool      `json:"can_receive_traffic" yaml:"can_receive_traffic"`
	CanWriteConfig    bool      `json:"can_write_config" yaml:"can_write_config"`
	LastHeartbeatAt   time.Time `json:"last_heartbeat_at,omitempty" yaml:"last_heartbeat_at,omitempty"`
	ConfigVersion     string    `json:"config_version,omitempty" yaml:"config_version,omitempty"`
	Reason            string    `json:"reason,omitempty" yaml:"reason,omitempty"`
}

func (s NodeStatus) ProductModeLabel(lang string) string {
	zh := lang == "zh" || lang == "zh-CN" || lang == "zh-Hans"
	switch s.Mode {
	case "single-node", "standalone":
		if zh {
			return "单机模式"
		}
		return "Standalone"
	case "ready":
		if zh {
			return "可接收流量"
		}
		return "Ready for traffic"
	case "reconnecting":
		if zh {
			return "重连中"
		}
		return "Reconnecting"
	case "protection":
		if zh {
			return "保护模式"
		}
		return "Protection mode"
	case "isolated":
		if zh {
			return "已隔离"
		}
		return "Isolated"
	case "maintenance":
		if zh {
			return "维护中"
		}
		return "Maintenance"
	default:
		if zh {
			return "初始化中"
		}
		return "Initializing"
	}
}
