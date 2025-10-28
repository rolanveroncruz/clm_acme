package http01

import (
	"runtime"
	"strings"
)

func getFunctionName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "unknown"
	}

	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}

	// The full name includes the package path (e.g., "main.myFunc").
	// You might want to strip the path for cleaner logging.
	fullName := fn.Name()

	// Optional: Strip the package path for a cleaner name
	parts := strings.Split(fullName, "/")
	name := parts[len(parts)-1]

	return name
}
