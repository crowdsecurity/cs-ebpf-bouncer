// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/cs-ebpf-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-ebpf-bouncer/pkg/metrics"
	"github.com/crowdsecurity/cs-ebpf-bouncer/pkg/xdp"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/ebpf/rlimit"
)

const bouncerType = "crowdsec-ebpf-bouncer"

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func Execute() error {
	configPath := flag.String("c", "", "path to crowdsec-ebpf-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("V", false, "display version and exit (deprecated)")
	flag.BoolVar(bouncerVersion, "version", *bouncerVersion, "display version and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Print(version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		return errors.New("configuration file is required")
	}

	configMerged, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configMerged))
		return nil
	}

	configExpanded := csstring.StrictExpand(string(configMerged), os.LookupEnv)

	config, err := cfg.NewConfig(strings.NewReader(configExpanded))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose && log.GetLevel() < log.DebugLevel {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("Starting %s %s", bouncerType, version.String())

	g, ctx := errgroup.WithContext(context.Background())

	bouncer := &csbouncer.StreamBouncer{}

	err = bouncer.ConfigReader(strings.NewReader(configExpanded))
	if err != nil {
		return err
	}

	bouncer.UserAgent = fmt.Sprintf("%s/%s", bouncerType, version.String())
	if err := bouncer.Init(); err != nil {
		return fmt.Errorf("unable to configure bouncer: %w", err)
	}

	if bouncer.InsecureSkipVerify != nil {
		log.Debugf("InsecureSkipVerify is set to %t", *bouncer.InsecureSkipVerify)
	}

	g.Go(func() error {
		bouncer.Run(ctx)
		return errors.New("bouncer stream halted")
	})

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to adjust memlock: %v\n", err)
		os.Exit(1)
	}

	cleanup, err := xdp.LoadXDP(config.Interface, config.MetricsEnabled)
	if err != nil {
		return fmt.Errorf("failed to load XDP: %w", err)
	}

	defer cleanup()
	xdp.Origin = xdp.NewOrigin()

	metricsProvider, err := csbouncer.NewMetricsProvider(bouncer.APIClient, bouncerType, metrics.MetricsUpdater, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("unable to create metrics provider: %w", err)
	}

	metrics.Map.MustRegisterAll()

	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})

	g.Go(func() error {
		log.Infof("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				return nil
			case decisions := <-bouncer.Stream:
				if decisions == nil {
					continue
				}
				//Update HERE the ebpf map
				for _, decision := range decisions.Deleted {

					if decision == nil {
						continue
					}

					if *decision.Scope == "Ip" {
						if isIPv6(*decision.Value) {
							continue
						}
						log.Debugf("Unblocking IP %s with reason %s", *decision.Value, *decision.Origin)
						xdp.UnblockIP(*decision.Value)
					}
				}
				for _, decision := range decisions.New {

					if decision == nil {
						continue
					}
					if *decision.Scope == "Ip" {

						if isIPv6(*decision.Value) { // Skip IPv6 for now
							continue
						}
						log.Debugf("Blocking IP %s with reason %s", *decision.Value, *decision.Origin)
						origin := ""
						if *decision.Origin == "lists" {
							origin = fmt.Sprintf("list:%s", *decision.Scenario)
						} else {
							origin = *decision.Origin
						}
						originId := xdp.Origin.Add(origin)

						if err := xdp.BlockIP(*decision.Value, originId); err != nil {
							log.Errorf("failed to block IP %s: %v", *decision.Value, err)
						}
					}
				}
			}
		}
	})

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}

func isIPv6(str string) bool {
	ip, err := netip.ParseAddr(str)
	if err != nil {
		return false
	}
	return ip.Is6()
}
