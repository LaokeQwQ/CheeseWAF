// Command cheesewaf-edr-sidecar is the metadata-only EDR event correlator.
// It implements the WAF sidecar lifecycle on stdin/stdout and the host data
// plane on inherited fd3/fd4. It never reads host processes, files, raw
// requests, cookies, tokens, or network data.
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
	"sync/atomic"

	"github.com/LaokeQwQ/CheeseWAF/internal/edr"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

const lifecycleProtocol = "cheesewaf-crp-sidecar-process.v1"

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

type edrHandler struct {
	client      *hostapi.Client
	engine      *edr.Engine
	policyEpoch atomic.Uint64
	mu          sync.Mutex
	mode        string
}

func (h *edrHandler) OnConfig(_ context.Context, cfg hostapi.Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if value, ok := cfg.Values["policy_epoch"]; ok {
		switch typed := value.(type) {
		case float64:
			if typed >= 0 {
				h.policyEpoch.Store(uint64(typed))
			}
		case json.Number:
			if parsed, err := typed.Int64(); err == nil && parsed >= 0 {
				h.policyEpoch.Store(uint64(parsed))
			}
		}
	}
	return nil
}

func (h *edrHandler) OnEvent(_ context.Context, payload json.RawMessage) error {
	var event edr.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	hints := h.engine.Observe(event, h.policyEpoch.Load())
	for _, hint := range hints {
		raw, err := json.Marshal(hint)
		if err != nil {
			return err
		}
		if err := h.client.SendHint(raw); err != nil {
			return err
		}
	}
	return nil
}

func (h *edrHandler) OnJob(context.Context, json.RawMessage) error { return nil }
func (h *edrHandler) OnDrain(context.Context) error                { return nil }
func (h *edrHandler) OnShutdown(context.Context) error             { return nil }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--describe" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"plugin_id": edr.PluginID, "version": edr.PluginVersion, "protocol": hostapi.ProtocolVersion,
			"rules": edr.RuleSummary(), "purpose": "metadata-only WAF event correlation; advisory hints only",
		})
		return
	}
	if err := run(); err != nil {
		_, _ = io.WriteString(os.Stderr, "edr-sidecar: "+err.Error()+"\n")
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
	var handler *edrHandler
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
		if request.SchemaVersion != lifecycleProtocol || request.Sequence == 0 {
			return fmt.Errorf("invalid lifecycle envelope")
		}
		ack := lifecycleAck{SchemaVersion: lifecycleProtocol, Sequence: request.Sequence, Operation: request.Operation, Status: "ok", Mode: mode}
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
					hostapi.CapabilityHealth,
					hostapi.CapabilityConfigRead,
				},
			})
			if err != nil {
				return err
			}
			handler = &edrHandler{client: client, engine: edr.NewEngine(), mode: mode}
			go func() {
				if err := client.Run(ctx, handler); err != nil && ctx.Err() == nil {
					_, _ = io.WriteString(os.Stderr, "edr data plane: "+err.Error()+"\n")
				}
			}()
		case "probe":
			// health is reported by the data plane
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
