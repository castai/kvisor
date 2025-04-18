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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	check2 "github.com/castai/kvisor/cmd/linter/kubebench/check"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// NewRunFilter constructs a Predicate based on FilterOpts which determines whether tested Checks should be run or not.
func NewRunFilter(opts FilterOpts) (check2.Predicate, error) {
	if opts.CheckList != "" && opts.GroupList != "" {
		return nil, fmt.Errorf("group option and check option can't be used together")
	}

	var groupIDs map[string]bool
	if opts.GroupList != "" {
		groupIDs = cleanIDs(opts.GroupList)
	}

	var checkIDs map[string]bool
	if opts.CheckList != "" {
		checkIDs = cleanIDs(opts.CheckList)
	}

	return func(g *check2.Group, c *check2.Check) bool {
		test := true
		if len(groupIDs) > 0 {
			_, ok := groupIDs[g.ID]
			test = test && ok
		}

		if len(checkIDs) > 0 {
			_, ok := checkIDs[c.ID]
			test = test && ok
		}

		test = test && (opts.Scored && c.Scored || opts.Unscored && !c.Scored)

		return test
	}, nil
}

func runChecks(nodetype check2.NodeType, testYamlFile, detectedVersion string) {
	// Verify config file was loaded into Viper during Cobra sub-command initialization.
	if configFileError != nil {
		colorPrint(check2.FAIL, fmt.Sprintf("Failed to read config file: %v\n", configFileError))
		os.Exit(1)
	}

	in, err := os.ReadFile(testYamlFile)
	if err != nil {
		exitWithError(fmt.Errorf("error opening %s test file: %v", testYamlFile, err))
	}

	glog.V(1).Info(fmt.Sprintf("Using test file: %s\n", testYamlFile))

	// Get the viper config for this section of tests
	typeConf := viper.Sub(string(nodetype))
	if typeConf == nil {
		colorPrint(check2.FAIL, fmt.Sprintf("No config settings for %s\n", string(nodetype)))
		os.Exit(1)
	}

	// Get the set of executables we need for this section of the tests
	binmap, err := getBinaries(typeConf, nodetype)
	// Checks that the executables we need for the section are running.
	if err != nil {
		glog.V(1).Info(fmt.Sprintf("failed to get a set of executables needed for tests: %v", err))
	}

	confmap := getFiles(typeConf, "config")
	svcmap := getFiles(typeConf, "service")
	kubeconfmap := getFiles(typeConf, "kubeconfig")
	cafilemap := getFiles(typeConf, "ca")
	datadirmap := getFiles(typeConf, "datadir")

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s, binSubs := makeSubstitutions(s, "bin", binmap)
	s, _ = makeSubstitutions(s, "conf", confmap)
	s, _ = makeSubstitutions(s, "svc", svcmap)
	s, _ = makeSubstitutions(s, "kubeconfig", kubeconfmap)
	s, _ = makeSubstitutions(s, "cafile", cafilemap)
	s, _ = makeSubstitutions(s, "datadir", datadirmap)

	controls, err := check2.NewControls(nodetype, []byte(s), detectedVersion)
	if err != nil {
		exitWithError(fmt.Errorf("error setting up %s controls: %v", nodetype, err))
	}

	runner := check2.NewRunner()
	filter, err := NewRunFilter(filterOpts)
	if err != nil {
		exitWithError(fmt.Errorf("error setting up run filter: %v", err))
	}

	generateDefaultEnvAudit(controls, binSubs)

	controls.RunChecks(runner, filter, parseSkipIds(skipIds))
	controlsCollection = append(controlsCollection, controls)
}

func generateDefaultEnvAudit(controls *check2.Controls, binSubs []string) {
	for _, group := range controls.Groups {
		for _, checkItem := range group.Checks {
			if checkItem.Tests != nil && !checkItem.DisableEnvTesting {
				for _, test := range checkItem.Tests.TestItems {
					if test.Env != "" && checkItem.AuditEnv == "" {
						binPath := ""

						if len(binSubs) == 1 {
							binPath = binSubs[0]
						} else {
							glog.V(1).Infof("AuditEnv not explicit for check (%s), where bin path cannot be determined", checkItem.ID)
						}

						if test.Env != "" && checkItem.AuditEnv == "" {
							checkItem.AuditEnv = fmt.Sprintf("cat \"/proc/$(/bin/ps -C %s -o pid= | tr -d ' ')/environ\" | tr '\\0' '\\n'", binPath)
						}
					}
				}
			}
		}
	}
}

func parseSkipIds(skipIds string) map[string]bool {
	skipIdMap := make(map[string]bool, 0)
	if skipIds != "" {
		for _, id := range strings.Split(skipIds, ",") {
			skipIdMap[strings.Trim(id, " ")] = true
		}
	}
	return skipIdMap
}

// colorPrint outputs the state in a specific colour, along with a message string
func colorPrint(state check2.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// prettyPrint outputs the results to stdout in human-readable format
func prettyPrint(r *check2.Controls, summary check2.Summary) {
	// Print check results.
	if !noResults {
		colorPrint(check2.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Text))
		for _, g := range r.Groups {
			colorPrint(check2.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Text))
			for _, c := range g.Checks {
				colorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Text))

				if includeTestOutput && c.State == check2.FAIL && len(c.ActualValue) > 0 {
					printRawOutput(c.ActualValue)
				}
			}
		}

		fmt.Println()
	}

	// Print remediations.
	if !noRemediations {
		if summary.Fail > 0 || summary.Warn > 0 {
			colors[check2.WARN].Printf("== Remediations %s ==\n", r.Type)
			for _, g := range r.Groups {
				for _, c := range g.Checks {
					if c.State == check2.FAIL {
						fmt.Printf("%s %s\n", c.ID, c.Remediation)
					}
					if c.State == check2.WARN {
						// Print the error if test failed due to problem with the audit command
						if c.Reason != "" && c.Type != "manual" {
							fmt.Printf("%s audit test did not run: %s\n", c.ID, c.Reason)
						} else {
							fmt.Printf("%s %s\n", c.ID, c.Remediation)
						}
					}
				}
			}
			fmt.Println()
		}
	}

	// Print summary setting output color to highest severity.
	if !noSummary {
		printSummary(summary, string(r.Type))
	}
}

func printSummary(summary check2.Summary, sectionName string) {
	var res check2.State
	if summary.Fail > 0 {
		res = check2.FAIL
	} else if summary.Warn > 0 {
		res = check2.WARN
	} else {
		res = check2.PASS
	}

	colors[res].Printf("== Summary %s ==\n", sectionName)
	fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n%d checks INFO\n\n",
		summary.Pass, summary.Fail, summary.Warn, summary.Info,
	)
}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func loadConfig(nodetype check2.NodeType, benchmarkVersion string) string {
	var file string
	var err error

	switch nodetype {
	case check2.MASTER:
		file = masterFile
	case check2.NODE:
		file = nodeFile
	case check2.CONTROLPLANE:
		file = controlplaneFile
	case check2.ETCD:
		file = etcdFile
	case check2.POLICIES:
		file = policiesFile
	case check2.MANAGEDSERVICES:
		file = managedservicesFile
	}

	path, err := getConfigFilePath(benchmarkVersion, file)
	if err != nil {
		exitWithError(fmt.Errorf("can't find %s controls file in %s: %v", nodetype, cfgDir, err))
	}

	// Merge version-specific config if any.
	mergeConfig(path)

	return filepath.Join(path, file)
}

func mergeConfig(path string) error {
	viper.SetConfigFile(path + "/config.yaml")
	err := viper.MergeInConfig()
	if err != nil {
		if os.IsNotExist(err) {
			glog.V(2).Info(fmt.Sprintf("No version-specific config.yaml file in %s", path))
		} else {
			return fmt.Errorf("couldn't read config file %s: %v", path+"/config.yaml", err)
		}
	}

	glog.V(1).Info(fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))

	return nil
}

func mapToBenchmarkVersion(kubeToBenchmarkMap map[string]string, kv string) (string, error) {
	kvOriginal := kv
	cisVersion, found := kubeToBenchmarkMap[kv]
	glog.V(2).Info(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	for !found && (kv != defaultKubeVersion && !isEmpty(kv)) {
		kv = decrementVersion(kv)
		cisVersion, found = kubeToBenchmarkMap[kv]
		glog.V(2).Info(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	}

	if !found {
		glog.V(1).Info(fmt.Sprintf("mapToBenchmarkVersion unable to find a match for: %q", kvOriginal))
		glog.V(3).Info(fmt.Sprintf("mapToBenchmarkVersion kubeToBenchmarkMap: %#v", kubeToBenchmarkMap))
		return "", fmt.Errorf("unable to find a matching Benchmark Version match for kubernetes version: %s", kvOriginal)
	}

	return cisVersion, nil
}

func loadVersionMapping(v *viper.Viper) (map[string]string, error) {
	kubeToBenchmarkMap := v.GetStringMapString("version_mapping")
	if kubeToBenchmarkMap == nil || (len(kubeToBenchmarkMap) == 0) {
		return nil, fmt.Errorf("config file is missing 'version_mapping' section")
	}

	return kubeToBenchmarkMap, nil
}

func loadTargetMapping(v *viper.Viper) (map[string][]string, error) {
	benchmarkVersionToTargetsMap := v.GetStringMapStringSlice("target_mapping")
	if len(benchmarkVersionToTargetsMap) == 0 {
		return nil, fmt.Errorf("config file is missing 'target_mapping' section")
	}

	return benchmarkVersionToTargetsMap, nil
}

func getBenchmarkVersion(kubeVersion, benchmarkVersion string, platform Platform, v *viper.Viper) (bv string, err error) {
	detecetedKubeVersion = "none"
	if !isEmpty(kubeVersion) && !isEmpty(benchmarkVersion) {
		return "", fmt.Errorf("It is an error to specify both --version and --benchmark flags")
	}
	if isEmpty(benchmarkVersion) && isEmpty(kubeVersion) && !isEmpty(platform.Name) {
		benchmarkVersion = getPlatformBenchmarkVersion(platform)
		if !isEmpty(benchmarkVersion) {
			detecetedKubeVersion = benchmarkVersion
		}
	}

	if isEmpty(benchmarkVersion) {
		if isEmpty(kubeVersion) {
			kv, err := getKubeVersion()
			if err != nil {
				return "", fmt.Errorf("Version check failed: %s\nAlternatively, you can specify the version with --version", err)
			}
			kubeVersion = kv.BaseVersion()
			detecetedKubeVersion = kubeVersion
		}

		kubeToBenchmarkMap, err := loadVersionMapping(v)
		if err != nil {
			return "", err
		}

		benchmarkVersion, err = mapToBenchmarkVersion(kubeToBenchmarkMap, kubeVersion)
		if err != nil {
			return "", err
		}

		glog.V(2).Info(fmt.Sprintf("Mapped Kubernetes version: %s to Benchmark version: %s", kubeVersion, benchmarkVersion))
	}

	glog.V(1).Info(fmt.Sprintf("Kubernetes version: %q to Benchmark version: %q", kubeVersion, benchmarkVersion))
	return benchmarkVersion, nil
}

// isMaster verify if master components are running on the node.
func isMaster() bool {
	return isThisNodeRunning(check2.MASTER)
}

// isEtcd verify if etcd components are running on the node.
func isEtcd() bool {
	return isThisNodeRunning(check2.ETCD)
}

func isThisNodeRunning(nodeType check2.NodeType) bool {
	glog.V(3).Infof("Checking if the current node is running %s components", nodeType)
	nodeTypeConf := viper.Sub(string(nodeType))
	if nodeTypeConf == nil {
		glog.V(2).Infof("No config for %s components found", nodeType)
		return false
	}

	components, err := getBinariesFunc(nodeTypeConf, nodeType)
	if err != nil {
		glog.V(2).Infof("Failed to find %s binaries: %v", nodeType, err)
		return false
	}
	if len(components) == 0 {
		glog.V(2).Infof("No %s binaries specified", nodeType)
		return false
	}

	glog.V(2).Infof("Node is running %s components", nodeType)
	return true
}

func exitCodeSelection(controlsCollection []*check2.Controls) int {
	for _, control := range controlsCollection {
		if control.Fail > 0 {
			return exitCode
		}
	}

	return 0
}

func writeOutput(controlsCollection []*check2.Controls) {
	sort.Slice(controlsCollection, func(i, j int) bool {
		iid, _ := strconv.Atoi(controlsCollection[i].ID)
		jid, _ := strconv.Atoi(controlsCollection[j].ID)
		return iid < jid
	})
	if junitFmt {
		writeJunitOutput(controlsCollection)
		return
	}
	if jsonFmt {
		writeJSONOutput(controlsCollection)
		return
	}
	writeStdoutOutput(controlsCollection)
}

func writeJSONOutput(controlsCollection []*check2.Controls) {
	var out []byte
	var err error
	if !noTotals {
		var totals check2.OverallControls
		totals.Controls = controlsCollection
		totals.Totals = getSummaryTotals(controlsCollection)
		out, err = json.Marshal(totals)
	} else {
		out, err = json.Marshal(controlsCollection)
	}
	if err != nil {
		exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
	}
	printOutput(string(out), outputFile)
}

func writeJunitOutput(controlsCollection []*check2.Controls) {
	// QuickFix for issue https://github.com/aquasecurity/kube-bench/issues/883
	// Should consider to deprecate of switch to using Junit template
	prefix := "<testsuites>\n"
	suffix := "\n</testsuites>"
	var outputAllControls []byte
	for _, controls := range controlsCollection {
		tempOut, err := controls.JUnit()
		outputAllControls = append(outputAllControls[:], tempOut[:]...)
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JUnit format: %v", err))
		}
	}
	printOutput(prefix+string(outputAllControls)+suffix, outputFile)
}

func writeStdoutOutput(controlsCollection []*check2.Controls) {
	for _, controls := range controlsCollection {
		summary := controls.Summary
		prettyPrint(controls, summary)
	}
	if !noTotals {
		printSummary(getSummaryTotals(controlsCollection), "total")
	}
}

func getSummaryTotals(controlsCollection []*check2.Controls) check2.Summary {
	var totalSummary check2.Summary
	for _, controls := range controlsCollection {
		summary := controls.Summary
		totalSummary.Fail = totalSummary.Fail + summary.Fail
		totalSummary.Warn = totalSummary.Warn + summary.Warn
		totalSummary.Pass = totalSummary.Pass + summary.Pass
		totalSummary.Info = totalSummary.Info + summary.Info
	}
	return totalSummary
}

func printRawOutput(output string) {
	for _, row := range strings.Split(output, "\n") {
		fmt.Println(fmt.Sprintf("\t %s", row))
	}
}

func writeOutputToFile(output string, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, output)
	return w.Flush()
}

func printOutput(output string, outputFile string) {
	if outputFile == "" {
		fmt.Println(output)
	} else {
		err := writeOutputToFile(output, outputFile)
		if err != nil {
			exitWithError(fmt.Errorf("Failed to write to output file %s: %v", outputFile, err))
		}
	}
}

// validTargets helps determine if the targets
// are legitimate for the benchmarkVersion.
func validTargets(benchmarkVersion string, targets []string, v *viper.Viper) (bool, error) {
	benchmarkVersionToTargetsMap, err := loadTargetMapping(v)
	if err != nil {
		return false, err
	}
	providedTargets, found := benchmarkVersionToTargetsMap[benchmarkVersion]
	if !found {
		return false, fmt.Errorf("No targets configured for %s", benchmarkVersion)
	}

	for _, pt := range targets {
		f := false
		for _, t := range providedTargets {
			if pt == strings.ToLower(t) {
				f = true
				break
			}
		}

		if !f {
			return false, nil
		}
	}

	return true, nil
}
