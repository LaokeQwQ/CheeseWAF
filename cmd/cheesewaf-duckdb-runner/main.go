// Command cheesewaf-duckdb-runner executes one reviewed, read-only DuckDB
// analysis job. DuckDB itself is host-provided; this binary never carries it.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/duckdb"
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

type jobRequest struct {
	SnapshotRef            string   `json:"snapshot_ref"`
	SnapshotManifestSHA256 string   `json:"snapshot_manifest_sha256"`
	SnapshotPaths          []string `json:"snapshot_paths"`
	TemplateID             string   `json:"template_id"`
	TemplateSQL            string   `json:"template_sql"`
	TemplateSHA256         string   `json:"template_sha256"`
	WindowFrom             string   `json:"window_from"`
	WindowTo               string   `json:"window_to"`
	EngineVersion          string   `json:"engine_version"`
	ExecutionProfileRef    string   `json:"execution_profile_ref"`
	ExecutionProfileSHA256 string   `json:"execution_profile_sha256"`
}

type duckDBHandler struct {
	client *hostapi.Client
	runner *duckdb.Runner
}

func (h *duckDBHandler) OnConfig(context.Context, hostapi.Config) error { return nil }
func (h *duckDBHandler) OnEvent(context.Context, json.RawMessage) error { return nil }

func (h *duckDBHandler) OnJob(ctx context.Context, payload json.RawMessage) error {
	var request jobRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return err
	}
	template, err := duckdb.LoadTemplate(request.TemplateID, []byte(request.TemplateSQL))
	if err != nil {
		return err
	}
	if request.TemplateSHA256 != "" && template.SHA256 != request.TemplateSHA256 {
		return fmt.Errorf("duckdb template digest mismatch")
	}
	from, err := time.Parse(time.RFC3339, request.WindowFrom)
	if err != nil {
		return err
	}
	to, err := time.Parse(time.RFC3339, request.WindowTo)
	if err != nil {
		return err
	}
	record, err := h.runner.Run(ctx, duckdb.Job{
		SnapshotRef: request.SnapshotRef, SnapshotManifestSHA256: request.SnapshotManifestSHA256,
		SnapshotPaths: request.SnapshotPaths, Template: template,
		WindowFrom: from, WindowTo: to, EngineVersion: request.EngineVersion,
		ExecutionProfileRef: request.ExecutionProfileRef, ExecutionProfileSHA256: request.ExecutionProfileSHA256,
		PluginID: "duckdb-analysis", PluginVersion: "1.0.0",
	})
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return h.client.SendAnalysis(raw)
}

func (h *duckDBHandler) OnDrain(context.Context) error    { return nil }
func (h *duckDBHandler) OnShutdown(context.Context) error { return nil }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--describe" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"plugin_id": "duckdb-analysis", "version": "1.0.0", "protocol": hostapi.ProtocolVersion,
			"purpose": "read-only DuckDB analysis job; host-provided engine; no arbitrary SQL",
		})
		return
	}
	if err := run(); err != nil {
		_, _ = io.WriteString(os.Stderr, "duckdb-runner: "+err.Error()+"\n")
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
	var handler *duckDBHandler
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
					hostapi.CapabilityAnalysisSubmit,
					hostapi.CapabilityHealth,
					hostapi.CapabilityConfigRead,
				},
			})
			if err != nil {
				return err
			}
			handler = &duckDBHandler{
				client: client,
				runner: duckdb.NewRunner(&duckdb.CLIExecutor{Binary: os.Getenv("CHEESEWAF_DUCKDB_BIN")}),
			}
			go func() {
				if err := client.Run(ctx, handler); err != nil && ctx.Err() == nil {
					_, _ = io.WriteString(os.Stderr, "duckdb data plane: "+err.Error()+"\n")
				}
			}()
		case "probe":
			// health is reported by the data plane
		case "mode":
			if mode == "observe" && request.Mode == "canary" || mode == "canary" && request.Mode == "active" {
				mode = request.Mode
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
