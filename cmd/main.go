package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/netboxlabs/orb-agent/agent"
	"github.com/netboxlabs/orb-agent/agent/backend/devicediscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/gnmidiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/gnmitelemetry"
	"github.com/netboxlabs/orb-agent/agent/backend/networkdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/opentelemetryinfinity"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/backend/snmpdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/snmptelemetry"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/netboxsync"
	"github.com/netboxlabs/orb-agent/agent/redact"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const (
	routineKey config.ContextKey = "routine"
)

var (
	cfgFiles   []string
	debug      bool
	renderOut  string
	renderTime time.Duration
)

func init() {
	devicediscovery.Register()
	gnmidiscovery.Register()
	networkdiscovery.Register()
	opentelemetryinfinity.Register()
	snmpdiscovery.Register()
	snmptelemetry.Register()
	gnmitelemetry.Register()
	pktvisor.Register()
	worker.Register()
}

// Version prints the version of the agent
func Version(_ *cobra.Command, _ []string) {
	fmt.Printf("orb-agent %s\n", version.GetBuildVersion())
	os.Exit(0)
}

// newRootLogger builds the agent's JSON logger on a mutable LevelVar so the
// level can be raised after the config file is parsed. The logger must exist
// before config.Load so the ORB_ env overlay can log through it; when debug
// comes only from the YAML file, the overlay's debug-level skip diagnostics
// are suppressed (the level is still Info while the file is being parsed) —
// only the -d flag captures those.
func newRootLogger(w io.Writer, debugFlag bool) (*slog.Logger, *slog.LevelVar) {
	level := new(slog.LevelVar) // defaults to Info
	if debugFlag {
		level.Set(slog.LevelDebug)
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, AddSource: false})
	return slog.New(h), level
}

// applyConfigDebug raises the log level to Debug when the config file asks
// for it (orb.debug.enable) and returns the effective debug state (flag OR
// config) that downstream consumers (BackendCommons.Debug, backend -d
// propagation) must see so YAML debug behaves exactly like -d.
func applyConfigDebug(logger *slog.Logger, level *slog.LevelVar, debugFlag bool, cfg config.Config) bool {
	if cfg.OrbAgent.Debug.Enable && !debugFlag {
		level.Set(slog.LevelDebug)
		logger.Debug("debug logging enabled via config file (orb.debug.enable)")
	}
	return debugFlag || cfg.OrbAgent.Debug.Enable
}

// Run starts the agent
func Run(_ *cobra.Command, _ []string) {
	if len(cfgFiles) == 0 {
		cobra.CheckErr(fmt.Errorf("no config file specified, use --config or -c flag to provide config files"))
	}

	// logger (constructed before Load so unknown ORB_ overrides can be logged)
	logger, logLevel := newRootLogger(os.Stdout, debug)

	configData, err := config.Load(cfgFiles, logger)
	if err != nil {
		cobra.CheckErr(fmt.Errorf("error loading configuration: %w", err))
	}

	logger.Info("backends loaded", "backends", redact.SensitiveData(configData.OrbAgent.Backends))

	effectiveDebug := applyConfigDebug(logger, logLevel, debug, configData)

	// new agent
	a, err := agent.New(logger, configData, effectiveDebug)
	if err != nil {
		logger.Error("agent start up error", "error", err)
		os.Exit(1)
	}

	// handle signals
	done := make(chan bool, 1)
	rootCtx, cancelFunc := context.WithCancel(context.WithValue(context.Background(), routineKey, "mainRoutine"))

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigs:
			logger.Warn("stop signal received stopping agent")
			a.Stop(rootCtx)
			cancelFunc()
			done <- true
			return
		case <-rootCtx.Done():
			logger.Warn("mainRoutine context cancelled")
			done <- true
			return
		}
	}()

	// start agent
	err = a.Start(rootCtx, cancelFunc)
	if err != nil {
		logger.Error("agent startup error", "error", err)
		os.Exit(1)
	}

	<-done
}

// NetBoxRender fetches the prefixes from the NetBox source configured in
// orb.config_manager.sources.netbox, prints or writes the policies the agent
// would generate, and exits without running anything.
func NetBoxRender(cmd *cobra.Command, _ []string) {
	if err := netboxRender(cmd.Context(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func netboxRender(ctx context.Context, stdout, stderr io.Writer) error {
	if len(cfgFiles) == 0 {
		return fmt.Errorf("no config file specified, use --config or -c flag to provide config files")
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	cfg, err := config.Load(cfgFiles, logger)
	if err != nil {
		return fmt.Errorf("error loading configuration: %w", err)
	}
	syncer, err := netboxsync.NewSyncer(cfg.OrbAgent.ConfigManager.Sources.NetBox, logger)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, renderTime)
	defer cancel()
	res, err := syncer.Run(ctx)
	if err != nil {
		return err
	}
	res.Summary.Log(logger)
	data, err := netboxsync.Render(res)
	if err != nil {
		return err
	}
	if renderOut == "" || renderOut == "-" {
		_, err = stdout.Write(data)
		return err
	}
	if err := netboxsync.WriteFileAtomic(renderOut, data, 0o644); err != nil {
		return err
	}
	logger.Info("wrote the generated policies", "path", renderOut)
	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use: "orb-agent",
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show agent version",
		Run:   Version,
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run orb-agent",
		Long:  `Run orb-agent`,
		Run:   Run,
	}

	runCmd.Flags().StringSliceVarP(&cfgFiles, "config", "c", []string{}, "Path to config files (may be specified multiple times)")
	runCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable verbose (debug level) output")

	renderCmd := &cobra.Command{
		Use:   "netbox-render",
		Short: "Render the policies the netbox config manager would generate, then exit",
		Long: `Read prefixes from the NetBox source in orb.config_manager.sources.netbox and
print (or write with -o) the network_discovery and snmp_discovery policies the
agent would generate, in the same shape as orb.policies. Nothing is scanned and
no policy is applied, so the output can be reviewed before running the agent.`,
		Run: NetBoxRender,
	}
	renderCmd.Flags().StringSliceVarP(&cfgFiles, "config", "c", []string{}, "Path to config files (may be specified multiple times)")
	renderCmd.Flags().StringVarP(&renderOut, "output", "o", "", "Write the policies to this file instead of stdout")
	renderCmd.Flags().DurationVar(&renderTime, "timeout", 5*time.Minute, "Overall timeout for reading NetBox")
	renderCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable verbose (debug level) output")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(renderCmd)
	rootCmd.AddCommand(versionCmd)
	_ = rootCmd.Execute()
}
