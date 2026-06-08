package decoder

import (
	"encoding/json"
	"fmt"
	"strings"
)

func FlattenJSON(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	var parts []string
	flatten(value, &parts)
	return strings.Join(parts, " ")
}

func flatten(value any, parts *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			*parts = append(*parts, key)
			flatten(item, parts)
		}
	case []any:
		for _, item := range v {
			flatten(item, parts)
		}
	case string:
		*parts = append(*parts, v)
	case float64, bool:
		*parts = append(*parts, fmt.Sprint(v))
	}
}
