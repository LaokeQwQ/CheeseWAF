// Command cheesewaf-control runs the standalone control-plane process.
// It owns native-raft membership and PostgreSQL control state; the WAF data
// plane remains a separate process and never waits on this command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlruntime "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/runtime"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string, out, errOut io.Writer) error {
	if parent == nil {
		parent = context.Background()
	}
	flags := flag.NewFlagSet("cheesewaf-control", flag.ContinueOnError)
	flags.SetOutput(errOut)
	profile := flags.String("profile", "production", "storage profile; only production is accepted")
	clusterID := flags.String("cluster-id", "", "stable cluster identity")
	nodeID := flags.String("node-id", "", "stable node identity; generated and persisted when omitted")
	dataDir := flags.String("data-dir", "", "native-raft data directory")
	listen := flags.String("listen", "127.0.0.1:9450", "local control HTTP listen address")
	raftListen := flags.String("raft-listen", "127.0.0.1:9451", "native-raft listen address")
	mode := flags.String("mode", string(nativeraft.ModeJoin), "raft mode: bootstrap or join")
	caFile := flags.String("ca-file", "", "native-raft CA certificate file")
	certFile := flags.String("cert-file", "", "native-raft node certificate file")
	keyFile := flags.String("key-file", "", "native-raft node private key file")
	postgresDSN := flags.String("postgres-dsn", "", "PostgreSQL management DSN (never printed)")
	timeout := flags.Duration("timeout", 15*time.Second, "startup timeout")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	opts := controlruntime.Options{Profile: *profile, ClusterID: *clusterID, NodeID: *nodeID, DataDir: *dataDir, Listen: *listen, RaftListen: *raftListen, Mode: nativeraft.StartMode(*mode), CAFile: *caFile, CertFile: *certFile, KeyFile: *keyFile, PostgreSQLDSN: *postgresDSN, Timeout: *timeout}
	if err := controlruntime.ValidateOptions(opts); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	startupCtx, startupCancel := context.WithTimeout(ctx, opts.Timeout)
	r, err := controlruntime.Open(startupCtx, opts)
	startupCancel()
	if err != nil {
		return fmt.Errorf("control-plane startup failed closed: %w", err)
	}
	defer r.Close()
	status := r.Status()
	fmt.Fprintf(out, "cheesewaf-control ready cluster=%s node=%s phase=%s write_ready=%t\n", status.ClusterID, status.NodeID, status.Phase, status.WriteReady)
	if err := r.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
