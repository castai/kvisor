// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kubebench

import (
	goflag "flag"
	"fmt"
	"os"

	check2 "github.com/castai/kvisor/cmd/kvisor/kubebench/check"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type FilterOpts struct {
	CheckList string
	GroupList string
	Scored    bool
	Unscored  bool
}

var (
	envVarsPrefix        = "KUBE_BENCH"
	defaultKubeVersion   = "1.18"
	kubeVersion          string
	detecetedKubeVersion string
	benchmarkVersion     string
	cfgFile              string
	cfgDir               = "./kubebench-rules/"
	jsonFmt              bool
	junitFmt             bool
	masterFile           = "master.yaml"
	nodeFile             = "node.yaml"
	etcdFile             = "etcd.yaml"
	controlplaneFile     = "controlplane.yaml"
	policiesFile         = "policies.yaml"
	managedservicesFile  = "managedservices.yaml"
	exitCode             int
	noResults            bool
	noSummary            bool
	noRemediations       bool
	skipIds              string
	noTotals             bool
	filterOpts           FilterOpts
	includeTestOutput    bool
	outputFile           string
	configFileError      error
	controlsCollection   []*check2.Controls
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-bench",
		Short: "Run CIS Benchmarks checks against a Kubernetes deployment",
		Long:  `This tool runs the CIS Kubernetes Benchmark (https://www.cisecurity.org/benchmark/kubernetes/)`,
		Run: func(cmd *cobra.Command, args []string) {
			bv, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, getPlatformInfo(), viper.GetViper())
			if err != nil {
				exitWithError(fmt.Errorf("unable to determine benchmark version: %v", err))
			}
			glog.V(1).Infof("Running checks for benchmark %v", bv)

			if isMaster() {
				glog.V(1).Info("== Running master checks ==")
				runChecks(check2.MASTER, loadConfig(check2.MASTER, bv), detecetedKubeVersion)

				// Control Plane is only valid for CIS 1.5 and later,
				// this a gatekeeper for previous versions
				valid, err := validTargets(bv, []string{string(check2.CONTROLPLANE)}, viper.GetViper())
				if err != nil {
					exitWithError(fmt.Errorf("error validating targets: %v", err))
				}
				if valid {
					glog.V(1).Info("== Running control plane checks ==")
					runChecks(check2.CONTROLPLANE, loadConfig(check2.CONTROLPLANE, bv), detecetedKubeVersion)
				}
			} else {
				glog.V(1).Info("== Skipping master checks ==")
			}

			// Etcd is only valid for CIS 1.5 and later,
			// this a gatekeeper for previous versions.
			valid, err := validTargets(bv, []string{string(check2.ETCD)}, viper.GetViper())
			if err != nil {
				exitWithError(fmt.Errorf("error validating targets: %v", err))
			}
			if valid && isEtcd() {
				glog.V(1).Info("== Running etcd checks ==")
				runChecks(check2.ETCD, loadConfig(check2.ETCD, bv), detecetedKubeVersion)
			} else {
				glog.V(1).Info("== Skipping etcd checks ==")
			}

			glog.V(1).Info("== Running node checks ==")
			runChecks(check2.NODE, loadConfig(check2.NODE, bv), detecetedKubeVersion)

			// Policies is only valid for CIS 1.5 and later,
			// this a gatekeeper for previous versions.
			valid, err = validTargets(bv, []string{string(check2.POLICIES)}, viper.GetViper())
			if err != nil {
				exitWithError(fmt.Errorf("error validating targets: %v", err))
			}
			if valid {
				glog.V(1).Info("== Running policies checks ==")
				runChecks(check2.POLICIES, loadConfig(check2.POLICIES, bv), detecetedKubeVersion)
			} else {
				glog.V(1).Info("== Skipping policies checks ==")
			}

			// Managedservices is only valid for GKE 1.0 and later,
			// this a gatekeeper for previous versions.
			valid, err = validTargets(bv, []string{string(check2.MANAGEDSERVICES)}, viper.GetViper())
			if err != nil {
				exitWithError(fmt.Errorf("error validating targets: %v", err))
			}
			if valid {
				glog.V(1).Info("== Running managed services checks ==")
				runChecks(check2.MANAGEDSERVICES, loadConfig(check2.MANAGEDSERVICES, bv), detecetedKubeVersion)
			} else {
				glog.V(1).Info("== Skipping managed services checks ==")
			}

			writeOutput(controlsCollection)
			os.Exit(exitCodeSelection(controlsCollection))
		},
	}

	cobra.OnInitialize(initConfig)

	// Output control
	cmd.PersistentFlags().IntVar(&exitCode, "exit-code", 0, "Specify the exit code for when checks fail")
	cmd.PersistentFlags().BoolVar(&noResults, "noresults", false, "Disable printing of results section")
	cmd.PersistentFlags().BoolVar(&noSummary, "nosummary", false, "Disable printing of summary section")
	cmd.PersistentFlags().BoolVar(&noRemediations, "noremediations", false, "Disable printing of remediations section")
	cmd.PersistentFlags().BoolVar(&noTotals, "nototals", false, "Disable printing of totals for failed, passed, ... checks across all sections")
	cmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	cmd.PersistentFlags().BoolVar(&junitFmt, "junit", false, "Prints the results as JUnit")
	cmd.PersistentFlags().BoolVar(&filterOpts.Scored, "scored", true, "Run the scored CIS checks")
	cmd.PersistentFlags().BoolVar(&filterOpts.Unscored, "unscored", true, "Run the unscored CIS checks")
	cmd.PersistentFlags().StringVar(&skipIds, "skip", "", "List of comma separated values of checks to be skipped")
	cmd.PersistentFlags().BoolVar(&includeTestOutput, "include-test-output", false, "Prints the actual result when test fails")
	cmd.PersistentFlags().StringVar(&outputFile, "outputfile", "", "Writes the results to output file when run with --json or --junit")

	cmd.PersistentFlags().StringVarP(
		&filterOpts.CheckList,
		"check",
		"c",
		"",
		`A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"`,
	)
	cmd.PersistentFlags().StringVarP(
		&filterOpts.GroupList,
		"group",
		"g",
		"",
		`Run all the checks under this comma-delimited list of groups. Example --group="1.1"`,
	)
	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./cfg/config.yaml)")
	cmd.PersistentFlags().StringVarP(&cfgDir, "config-dir", "D", cfgDir, "config directory")
	cmd.PersistentFlags().StringVar(&kubeVersion, "version", "", "Manually specify Kubernetes version, automatically detected if unset")
	cmd.PersistentFlags().StringVar(&benchmarkVersion, "benchmark", "", "Manually specify CIS benchmark version. It would be an error to specify both --version and --benchmark flags")

	if err := goflag.Set("logtostderr", "true"); err != nil {
		fmt.Printf("unable to set logtostderr: %+v\n", err)
		os.Exit(-1)
	}
	goflag.CommandLine.VisitAll(func(goflag *goflag.Flag) {
		cmd.PersistentFlags().AddGoFlag(goflag)
	})

	return cmd
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config") // name of config file (without extension)
		viper.AddConfigPath(cfgDir)   // adding ./cfg as first search path
	}

	// Read flag values from environment variables.
	// Precedence: Command line flags take precedence over environment variables.
	viper.SetEnvPrefix(envVarsPrefix)
	viper.AutomaticEnv()

	if kubeVersion == "" {
		if env := viper.Get("version"); env != nil {
			kubeVersion = env.(string)
		}
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error for now to prevent commands
			// which don't need the config file exiting.
			configFileError = err
		} else {
			// Config file was found but another error was produced
			colorPrint(check2.FAIL, fmt.Sprintf("Failed to read config file: %v\n", err))
			os.Exit(1)
		}
	}
}
