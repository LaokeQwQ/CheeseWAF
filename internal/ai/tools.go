package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

func NewDefaultRegistry(cfg *config.Config) *Registry {
	registry := NewRegistry()
	registry.Register(SystemSummaryTool{Config: cfg})
	return registry
}

func (r *Registry) Register(tool Tool) {
	if r == nil || tool == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name()] = tool
}

func (r *Registry) Get(name string) (Tool, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	return tool, ok
}

func (r *Registry) List() []Tool {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		out = append(out, tool)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

func (r *Registry) ListForLLM() []map[string]any {
	tools := r.List()
	out := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        tool.Name(),
				"description": tool.Description(),
				"parameters":  tool.Parameters(),
			},
		})
	}
	return out
}

type SystemSummaryTool struct {
	Config *config.Config
}

func (SystemSummaryTool) Name() string {
	return "system_summary"
}

func (SystemSummaryTool) Description() string {
	return "Read CheeseWAF runtime configuration summary without secrets."
}

func (SystemSummaryTool) Sensitivity() ToolSensitivity {
	return ReadOnly
}

func (SystemSummaryTool) Parameters() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (t SystemSummaryTool) Execute(context.Context, map[string]any) (*ToolResult, error) {
	if t.Config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	summary := map[string]any{
		"sites":          len(t.Config.Sites),
		"bot_enabled":    t.Config.Protection.Bot.Enabled,
		"edge_cache":     t.Config.Edge.Cache.Enabled,
		"scheduler":      t.Config.Scheduler.Enabled,
		"waf_modes":      map[string]string{},
		"admin_listener": t.Config.Server.AdminListen,
	}
	modes := summary["waf_modes"].(map[string]string)
	for _, site := range t.Config.Sites {
		modes[site.ID] = site.WAF.Mode
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, err
	}
	return &ToolResult{Success: true, Output: string(data)}, nil
}
