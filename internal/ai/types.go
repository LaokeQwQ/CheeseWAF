// Package ai defines interfaces for the AI assistant tool system.
package ai

import "context"

// ToolSensitivity represents the sensitivity level of an AI tool.
// Sensitivity level of an AI tool.
type ToolSensitivity int

const (
	// ReadOnly tools can be executed without user confirmation.
	// Read-only tool; runs without user confirmation.
	ReadOnly ToolSensitivity = iota

	// Modify tools require a diff preview and user confirmation before execution.
	// Mutating tool; requires a diff preview and user confirmation.
	Modify

	// Destructive tools require password re-verification + confirmation.
	// Dangerous tool; requires password re-verification plus confirmation.
	Destructive
)

// ToolResult represents the result of a tool execution.
// Tool execution result.
type ToolResult struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`         // 输出内容
	Diff    string `json:"diff,omitempty"` // 变更预览 (modify 级别)
	Error   string `json:"error,omitempty"`
}

type AssistantToolCall struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Sensitivity string           `json:"sensitivity"`
	Args        map[string]any   `json:"args,omitempty"`
	Result      *ToolResult      `json:"result,omitempty"`
	Approval    *ApprovalRequest `json:"approval,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// AssistantTraceEvent is an operator-visible audit trail for the assistant
// agent loop. It records what happened at the tool gateway boundary without
// exposing hidden chain-of-thought.
type AssistantTraceEvent struct {
	Type         string           `json:"type"`
	Message      string           `json:"message"`
	Provider     string           `json:"provider,omitempty"`
	Model        string           `json:"model,omitempty"`
	Mode         string           `json:"mode,omitempty"`
	ToolName     string           `json:"tool_name,omitempty"`
	Args         map[string]any   `json:"args,omitempty"`
	Result       *ToolResult      `json:"result,omitempty"`
	Approval     *ApprovalRequest `json:"approval,omitempty"`
	Error        string           `json:"error,omitempty"`
	At           string           `json:"at,omitempty"`
	InputTokens  int              `json:"input_tokens,omitempty"`
	OutputTokens int              `json:"output_tokens,omitempty"`
	TotalTokens  int              `json:"total_tokens,omitempty"`
}

func SensitivityName(value ToolSensitivity) string {
	switch value {
	case ReadOnly:
		return "read_only"
	case Modify:
		return "modify"
	case Destructive:
		return "destructive"
	default:
		return "unknown"
	}
}

// ToolPreviewer can be implemented by tools that need to show an exact
// operator-visible diff before approval.
type ToolPreviewer interface {
	Preview(ctx context.Context, args map[string]any) (string, error)
}

// ToolPreviewResolver additionally returns an opaque binding for tools whose
// approval preview must be revalidated against a durable state snapshot.
// Bindings are server-created and never accepted from operator input.
type ToolPreviewResolver interface {
	ResolvePreview(ctx context.Context, args map[string]any) (diff string, binding string, err error)
}

type toolPreviewBindingContextKey struct{}

func ContextWithToolPreviewBinding(ctx context.Context, binding string) context.Context {
	return context.WithValue(ctx, toolPreviewBindingContextKey{}, binding)
}

func ToolPreviewBindingFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	binding, _ := ctx.Value(toolPreviewBindingContextKey{}).(string)
	return binding
}

// ToolPermissioner declares an additional RBAC permission required by a tool.
// The assistant keeps the declaration optional so existing tools remain
// compatible while sensitive data readers can enforce their own scope.
type ToolPermissioner interface {
	RequiredPermission() string
}

// Tool is the interface for AI assistant internal tools.
// Each tool declares its sensitivity level for the approval flow.
// Internal AI assistant tool; each tool declares its own sensitivity level.
type Tool interface {
	// Name returns the tool name.
	// Returns the tool name.
	Name() string

	// Description is shown to operators and sent to the model as the tool description.
	// Shown to the operator and used as the tool description for the model.
	Description() string

	// Sensitivity returns the tool's sensitivity level.
	// Returns the tool sensitivity level.
	Sensitivity() ToolSensitivity

	// Parameters returns the JSON Schema for the tool's parameters.
	// Returns the JSON Schema for the tool arguments.
	Parameters() map[string]any

	// Execute runs the tool with the given arguments.
	// Executes the tool with the given arguments.
	Execute(ctx context.Context, args map[string]any) (*ToolResult, error)
}

// ToolRegistry manages registered AI tools.
// AI tool registry.
type ToolRegistry interface {
	// Register adds a tool to the registry.
	// Register a tool.
	Register(tool Tool)

	// Get returns a tool by name.
	// Get a tool by name.
	Get(name string) (Tool, bool)

	// List returns all registered tools.
	// List all registered tools.
	List() []Tool

	// ListForLLM returns tool definitions in the model function-calling schema.
	// Returns the tool definitions used by the model function-calling protocol.
	ListForLLM() []map[string]any
}
