package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/vpp/agent"
)

func NewDiscoverCmd(glob *Flags) *cobra.Command {
	var (
		opts DiscoverOptions
	)
	cmd := &cobra.Command{
		Use:     "discover",
		Aliases: []string{"discovery"},
		Short:   "Discover VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDiscover(*glob, opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.PrintCLIs, "printclis", false, "Additional CLI commands to run for each instance")
	flags.BoolVar(&opts.IsNsm, "nsm", false, "Assume NSM VPP deployments.")
	flags.BoolVar(&opts.IPsecAgg, "ipsec-agg", false, "aggregate IPSec info")
	flags.StringSliceVar(&opts.ExtraCLIs, "extraclis", nil, "Additional CLI commands to run for each instance")
	return cmd
}

type DiscoverOptions struct {
	ExtraCLIs []string
	PrintCLIs bool
	IsNsm bool
	IPsecAgg bool
}

func RunDiscover(glob Flags, opts DiscoverOptions) error {
	ctl, err := SetupController(glob)
	if err != nil {
		return fmt.Errorf("provider setup error: %w", err)
	}

	if err := ctl.DiscoverInstances(glob.Queries...); err != nil {
		return err
	}
	instances := ctl.Instances()

	logrus.Infof("discovered %d vpp instances", len(instances))

	var vppInstances []*agent.Instance

	for _, instance := range instances {
		logrus.Debugf("- instance %+v: %v", instance.ID(), instance.Status())

		vpp, err := agent.NewInstance(instance.Probe())
		if err != nil {
			logrus.Error("instance %v error: %v", instance.ID(), err)
			continue
		}
		vppInstances = append(vppInstances, vpp)

		vpp.Version = instance.VersionInfo().Version
		agent.RunCLIs(vpp, opts.ExtraCLIs)

		agent.PrintInstance(vpp)
		if opts.PrintCLIs {
			agent.PrintCLIs(vpp)
		}
	}

	if opts.IsNsm && opts.IPsecAgg {
		logrus.Infof("Aggregating NSM IPSec info for instances")
		agent.PrintCorrelatedNsmIpSec(os.Stdout, vppInstances)
	}

	return nil
}
