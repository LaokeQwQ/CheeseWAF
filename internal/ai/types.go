// Package ai defines interfaces for the AI assistant tool system.
package ai

import "context"

// ToolSensitivity represents the sensitivity level of an AI tool.
// AI 工具的敏感度级别。
type ToolSensitivity int

const (
	// ReadOnly tools can be executed without user confirmation.
	// 只读工具，无需用户确认即可执行。
	ReadOnly ToolSensitivity = iota

	// Modify tools require a diff preview and user confirmation before execution.
	// 修改类工具，执行前需展示 diff 预览并获得用户确认。
	Modify

	// Destructive tools require password re-verification + confirmation.
	// 危险操作工具，需密码二次验证 + 确认。
	Destructive
)

// ToolResult represents the result of a tool execution.
// 工具执行结果。
type ToolResult struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`         // 输出内容
	Diff    string `json:"diff,omitempty"` // 变更预览 (modify 级别)
	Error   string `json:"error,omitempty"`
}

// Tool is the interface for AI assistant internal tools.
// Each tool declares its sensitivity level for the approval flow.
// AI 助手内部工具接口，每个工具声明自己的敏感度级别。
type Tool interface {
	// Name returns the tool name.
	// 返回工具名称。
	Name() string

	// Description returns a human-readable description (also used as LLM tool description).
	// 返回人类可读描述（同时作为 LLM 的 tool description）。
	Description() string

	// Sensitivity returns the tool's sensitivity level.
	// 返回工具的敏感度级别。
	Sensitivity() ToolSensitivity

	// Parameters returns the JSON Schema for the tool's parameters.
	// 返回工具参数的 JSON Schema。
	Parameters() map[string]any

	// Execute runs the tool with the given arguments.
	// 使用给定参数执行工具。
	Execute(ctx context.Context, args map[string]any) (*ToolResult, error)
}

// ToolRegistry manages registered AI tools.
// AI 工具注册中心。
type ToolRegistry interface {
	// Register adds a tool to the registry.
	// 注册工具。
	Register(tool Tool)

	// Get returns a tool by name.
	// 按名称获取工具。
	Get(name string) (Tool, bool)

	// List returns all registered tools.
	// 列出所有已注册工具。
	List() []Tool

	// ListForLLM returns tool definitions formatted for the LLM API (OpenAI function calling format).
	// 返回格式化为 LLM API 的工具定义（OpenAI function calling 格式）。
	ListForLLM() []map[string]any
}
