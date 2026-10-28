// Command cheesewaf-plugin-conformance is a minimal sidecar used by the host
// data-plane integration tests. It implements the lifecycle protocol on
// stdin/stdout and the host data plane on inherited fd3/fd4.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

const protocol = "cheesewaf-crp-sidecar-process.v1"

type lifecycleRequest struct {
	SchemaVersion string           `json:"schema_version"`
	Sequence      uint64           `json:"sequence"`
	Operation     string           `json:"operation"`
	Mode          string           `json:"mode"`
	Identity      hostapi.Identity `json:"identity"`
}

type lifecycleAck struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
	Mode          string `json:"mode"`
}

type conformanceHandler struct {
	client *hostapi.Client
	mu     sync.Mutex
	mode   string
}

func (h *conformanceHandler) OnConfig(context.Context, hostapi.Config) error { return nil }
func (h *conformanceHandler) OnEvent(context.Context, json.RawMessage) error {
	if os.Getenv("CHEESEWAF_CONFORMANCE_CRASH") == "1" {
		os.Exit(3)
	}
	return h.client.SendHint(json.RawMessage(`{"hint_id":"hint-1","plugin_id":"conformance"}`))
}
func (h *conformanceHandler) OnJob(context.Context, json.RawMessage) error {
	return h.client.SendAnalysis(json.RawMessage(`{"record_id":"analysis-1","plugin_id":"conformance"}`))
}
func (h *conformanceHandler) OnDrain(context.Context) error    { return nil }
func (h *conformanceHandler) OnShutdown(context.Context) error { return nil }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--describe" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"plugin_id": "conformance", "version": "1.0.0", "protocol": hostapi.ProtocolVersion,
			"purpose": "host data-plane conformance helper",
		})
		return
	}
	if err := run(); err != nil {
		_, _ = io.WriteString(os.Stderr, "conformance: "+err.Error()+"\n")
		os.Exit(2)
	}
}

func run() error {
	hostToPlugin := os.NewFile(3, "host-to-plugin")
	pluginToHost := os.NewFile(4, "plugin-to-host")
	if hostToPlugin == nil || pluginToHost == nil {
		return fmt.Errorf("fd3/fd4 are required")
	}
	defer hostToPlugin.Close()
	defer pluginToHost.Close()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64<<10), 64<<10)
	encoder := json.NewEncoder(os.Stdout)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var client *hostapi.Client
	var handler *conformanceHandler
	mode := "observe"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var request lifecycleRequest
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			return fmt.Errorf("invalid lifecycle frame: %w", err)
		}
		if request.SchemaVersion != protocol || request.Sequence == 0 {
			return fmt.Errorf("invalid lifecycle envelope")
		}
		ack := lifecycleAck{SchemaVersion: protocol, Sequence: request.Sequence, Operation: request.Operation, Status: "ok", Mode: mode}
		switch request.Operation {
		case "start":
			if client != nil {
				return fmt.Errorf("duplicate start")
			}
			var err error
			client, err = hostapi.NewClient(hostToPlugin, pluginToHost, hostapi.ClientOptions{
				Identity: request.Identity,
				Capabilities: []hostapi.Capability{
					hostapi.CapabilityEventsSubscribe,
					hostapi.CapabilityHintsSubmit,
					hostapi.CapabilityAnalysisSubmit,
					hostapi.CapabilityHealth,
				},
			})
			if err != nil {
				return err
			}
			handler = &conformanceHandler{client: client, mode: mode}
			go func() {
				if err := client.Run(ctx, handler); err != nil && ctx.Err() == nil {
					_, _ = io.WriteString(os.Stderr, "conformance data plane: "+err.Error()+"\n")
				}
			}()
		case "probe":
			// no-op
		case "mode":
			if mode == "observe" && request.Mode == "canary" || mode == "canary" && request.Mode == "active" {
				mode = request.Mode
				if handler != nil {
					handler.mu.Lock()
					handler.mode = mode
					handler.mu.Unlock()
				}
				ack.Mode = mode
			} else {
				return fmt.Errorf("invalid mode transition")
			}
		case "stop":
			ack.Mode = mode
			if err := encoder.Encode(ack); err != nil {
				return err
			}
			cancel()
			if client != nil {
				_ = client.Close()
			}
			return nil
		default:
			return fmt.Errorf("unknown operation %q", request.Operation)
		}
		if err := encoder.Encode(ack); err != nil {
			return err
		}
	}
	return scanner.Err()
}
