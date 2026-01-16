//go:build arm64

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	ErrCodeUnknown         = 1000
	ErrCodeTriggerLaunch   = 1100
	ErrCodeAutoStop        = 1200
	ErrCodeProbeLifecycle  = 1300
)

var logJSONOutput bool

type LogField map[string]any

func logEvent(level string, msg string, code int, fields LogField) {
	if logJSONOutput {
		entry := map[string]any{
			"ts":    time.Now().Format(time.RFC3339Nano),
			"level": level,
			"msg":   msg,
			"code":  code,
		}
		for k, v := range fields {
			entry[k] = v
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(entry)
		return
	}

	var parts []string
	if code != 0 {
		parts = append(parts, fmt.Sprintf("code=%d", code))
	}
	if len(fields) > 0 {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
		}
	}
	if len(parts) > 0 {
		log.Printf("[%s] %s (%s)", strings.ToUpper(level), msg, strings.Join(parts, " "))
	} else {
		log.Printf("[%s] %s", strings.ToUpper(level), msg)
	}
}
