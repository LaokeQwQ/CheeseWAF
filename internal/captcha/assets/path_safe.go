package assets

import "github.com/LaokeQwQ/CheeseWAF/internal/fsguard"

func safeConfigPath(path string) (string, error) {
	return fsguard.SafeConfigPath(path)
}

func safeConfigPathUnderRoot(path, root string) (string, error) {
	return fsguard.SafeConfigPathUnderRoot(path, root)
}

func safePathComponent(name string) error {
	return fsguard.SafePathComponent(name)
}
