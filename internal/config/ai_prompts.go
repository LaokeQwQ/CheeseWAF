package config

import (
	"fmt"
	"strings"
)

// AIPromptConfig is an explicitly versioned operator-managed prompt addition.
// It is appended after the immutable platform safety policy.
type AIPromptConfig struct {
	ID       string `yaml:"id" json:"id"`
	Version  string `yaml:"version" json:"version"`
	Content  string `yaml:"content" json:"content"`
	Language string `yaml:"language" json:"language"`
	Model    string `yaml:"model" json:"model"`
	Enabled  bool   `yaml:"enabled" json:"enabled"`
}

type AISkillConfig struct {
	ID                  string   `yaml:"id" json:"id"`
	Version             string   `yaml:"version" json:"version"`
	PromptID            string   `yaml:"prompt_id" json:"prompt_id"`
	Tools               []string `yaml:"tools" json:"tools"`
	RequiredPermissions []string `yaml:"required_permissions" json:"required_permissions"`
	KnowledgeIDs        []string `yaml:"knowledge_ids" json:"knowledge_ids"`
	Enabled             bool     `yaml:"enabled" json:"enabled"`
}

func ValidateAIPromptRegistry(cfg AIConfig) error {
	if len(cfg.Prompts) > 32 || len(cfg.Skills) > 32 {
		return fmt.Errorf("AI prompt and skill registries are limited to 32 entries")
	}
	prompts := make(map[string]bool)
	for _, p := range cfg.Prompts {
		if !validAIRegistryID(p.ID) || !validAIRegistryID(p.Version) || len(p.Content) == 0 || len(p.Content) > 8192 || len(p.Language) > 32 || len(p.Model) > 256 || prompts[p.ID] {
			return fmt.Errorf("AI prompt requires unique id, version and at most 8192 bytes of content")
		}
		prompts[p.ID] = true
	}
	seen := map[string]bool{}
	for _, skill := range cfg.Skills {
		if !validAIRegistryID(skill.ID) || !validAIRegistryID(skill.Version) || seen[skill.ID] || !prompts[skill.PromptID] || len(skill.Tools) > 32 || len(skill.RequiredPermissions) > 32 || len(skill.KnowledgeIDs) > 64 {
			return fmt.Errorf("AI skill requires unique id, version, a registered prompt, and bounded scopes")
		}
		for _, tool := range skill.Tools {
			if !validAIRegistryID(tool) {
				return fmt.Errorf("AI skill has invalid tool name")
			}
		}
		for _, permission := range skill.RequiredPermissions {
			if len(permission) > 128 || strings.TrimSpace(permission) == "" || strings.Contains(permission, "*") {
				return fmt.Errorf("AI skill requires explicit permission names")
			}
		}
		seen[skill.ID] = true
	}
	return nil
}
func validAIRegistryID(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
