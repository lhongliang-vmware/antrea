// Copyright 2021 Antrea Authors
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

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	legacycorev1a2 "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacysecv1alpha1 "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
	. "github.com/vmware-tanzu/antrea/test/e2e/utils"
)

func testLegacyInvalidACNPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without a priority accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-priority").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	acnp := builder.GetLegacy()
	log.Debugf("creating legacy ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyANPBasic(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "np-same-name").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, nil, secv1alpha1.RuleActionDrop, "")
	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("x/b"), Pod("y/a"), false)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop X/B to Y/A", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPDropEgress tests that a ACNP is able to drop egress traffic from pods labelled A to namespace Z.
func testLegacyACNPDropEgress(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, nil, secv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("x/a"), Pod("z/a"), false)
	reachability.Expect(Pod("x/a"), Pod("z/b"), false)
	reachability.Expect(Pod("x/a"), Pod("z/c"), false)
	reachability.Expect(Pod("y/a"), Pod("z/a"), false)
	reachability.Expect(Pod("y/a"), Pod("z/b"), false)
	reachability.Expect(Pod("y/a"), Pod("z/c"), false)
	reachability.Expect(Pod("z/a"), Pod("z/b"), false)
	reachability.Expect(Pod("z/a"), Pod("z/c"), false)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to NS:z", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPPortRange tests the port range in a ACNP can work.
func testLegacyACNPPortRange(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8080, nil, &p8085, nil, nil, map[string]string{"ns": "z"},
		nil, nil, nil, secv1alpha1.RuleActionDrop, "", "acnp-port-range")

	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("x/a"), Pod("z/a"), false)
	reachability.Expect(Pod("x/a"), Pod("z/b"), false)
	reachability.Expect(Pod("x/a"), Pod("z/c"), false)
	reachability.Expect(Pod("y/a"), Pod("z/a"), false)
	reachability.Expect(Pod("y/a"), Pod("z/b"), false)
	reachability.Expect(Pod("y/a"), Pod("z/c"), false)
	reachability.Expect(Pod("z/a"), Pod("z/b"), false)
	reachability.Expect(Pod("z/a"), Pod("z/c"), false)

	var testSteps []*TestStep
	testSteps = append(testSteps, &TestStep{
		fmt.Sprintf("ACNP Drop Port 8080:8085"),
		reachability,
		[]metav1.Object{builder.GetLegacy()},
		nil,
		[]int32{8080, 8081, 8082, 8083, 8084, 8085},
		0,
		nil,
	})

	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to NS:z with a portRange", testSteps},
	}
	executeLegacyTests(t, testCase)
}

func testLegacyInvalidACNPPortRangeEndPortSmall(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy egress rule with endPort smaller than port accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8082, nil, &p8081, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, secv1alpha1.RuleActionDrop, "", "acnp-port-range")

	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPIngressPeerCGSetWithIPBlock(t *testing.T) {
	cgA := "cg-a"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateLegacyCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and ipBlock in NetworkPolicyPeer set")
	cidr := "10.0.0.10/32"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-ipblock-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: "cg-a"}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, &cidr, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, []ACNPAppliedToSpec{{Group: "cg-a"}}, secv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

// executeTests runs all the tests in testList and prints results
func executeLegacyTests(t *testing.T, testList []*TestCase) {
	executeLegacyTestsWithData(t, testList, nil)
}

func executeLegacyTestsWithData(t *testing.T, testList []*TestCase, data *TestData) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyLegacyTestStepServicesAndGroups(t, step)
			applyLegacyTestStepPolicies(t, step)
			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				for _, port := range step.Port {
					k8sUtils.Validate(allPods, reachability, port)
				}
				step.Duration = time.Now().Sub(start)
				reachability.PrintSummary(true, true, true)

				_, wrong, _ := step.Reachability.Summary()
				if wrong != 0 {
					t.Errorf("failure -- %d wrong results", wrong)
				}
			}
			if len(step.CustomProbes) > 0 && data == nil {
				t.Errorf("test case %s with custom probe must set test data", testCase.Name)
				continue
			}
			for _, p := range step.CustomProbes {
				doProbe(t, data, p)
			}
		}
		log.Debugf("Cleaning-up all policies and groups created by this Testcase and sleeping for %v", networkPolicyDelay)
		cleanupLegacyTestCasePolicies(t, testCase)
		cleanupLegacyTestCaseServicesAndGroups(t, testCase)
	}
	allTestList = append(allTestList, testList...)
}

func applyLegacyTestStepPolicies(t *testing.T, step *TestStep) {
	for _, policy := range step.Policies {
		switch p := policy.(type) {
		case *legacysecv1alpha1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateLegacyACNP(p)
			failOnError(err, t)
		case *legacysecv1alpha1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateLegacyANP(p)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(p)
			failOnError(err, t)
		}
	}
	if len(step.Policies) > 0 {
		log.Debugf("Sleeping for %v for all policies to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func cleanupLegacyTestCasePolicies(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same policy.
	// Use sets to avoid duplicates.
	acnpsToDelete, anpsToDelete, npsToDelete := sets.String{}, sets.String{}, sets.String{}
	for _, step := range c.Steps {
		for _, policy := range step.Policies {
			switch p := policy.(type) {
			case *legacysecv1alpha1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(p.Name)
			case *legacysecv1alpha1.NetworkPolicy:
				anpsToDelete.Insert(p.Namespace + "/" + p.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(p.Namespace + "/" + p.Name)
			}
		}
	}
	for _, acnp := range acnpsToDelete.List() {
		failOnError(k8sUtils.DeleteLegacyACNP(acnp), t)
	}
	for _, anp := range anpsToDelete.List() {
		failOnError(k8sUtils.DeleteLegacyANP(strings.Split(anp, "/")[0], strings.Split(anp, "/")[1]), t)
	}
	for _, np := range npsToDelete.List() {
		failOnError(k8sUtils.DeleteNetworkPolicy(strings.Split(np, "/")[0], strings.Split(np, "/")[1]), t)
	}
	if acnpsToDelete.Len()+anpsToDelete.Len()+npsToDelete.Len() > 0 {
		log.Debugf("Sleeping for %v for all policy deletions to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func applyLegacyTestStepServicesAndGroups(t *testing.T, step *TestStep) {
	for _, obj := range step.ServicesAndGroups {
		switch o := obj.(type) {
		case *legacycorev1a2.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateLegacyCG(o)
			failOnError(err, t)
		case *v1.Service:
			_, err := k8sUtils.CreateOrUpdateService(o)
			failOnError(err, t)
		}
	}
	if len(step.ServicesAndGroups) > 0 {
		log.Debugf("Sleeping for %v for all groups to have members computed", groupDelay)
		time.Sleep(groupDelay)
	}
}

func cleanupLegacyTestCaseServicesAndGroups(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same Group/Service.
	// Use sets to avoid duplicates.
	svcsToDelete, groupsToDelete := sets.String{}, sets.String{}
	for _, step := range c.Steps {
		for _, obj := range step.ServicesAndGroups {
			switch o := obj.(type) {
			case *legacycorev1a2.ClusterGroup:
				groupsToDelete.Insert(o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for _, cg := range groupsToDelete.List() {
		failOnError(k8sUtils.DeleteLegacyCG(cg), t)
	}
	for _, svc := range svcsToDelete.List() {
		failOnError(k8sUtils.DeleteService(strings.Split(svc, "/")[0], strings.Split(svc, "/")[1]), t)
	}
}

func TestLegacyAntreaPolicy(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	initialize(t, data)

	t.Run("TestLegacyAntreaPolicy", func(t *testing.T) {
		t.Run("Case=LegacyANPBasic", func(t *testing.T) { testLegacyANPBasic(t) })
		t.Run("Case=LegacyACNPPortRangePortEndPortSmallDenied", func(t *testing.T) { testLegacyInvalidACNPPortRangeEndPortSmall(t) })
		t.Run("Case=LegacyACNPIngressPeerCGSetWithIPBlock", func(t *testing.T) { testLegacyInvalidACNPIngressPeerCGSetWithIPBlock(t) })
		t.Run("Case=LegacyACNPPortRange", func(t *testing.T) { testLegacyACNPPortRange(t) })
		t.Run("Case=LegacyACNPNoPriority", func(t *testing.T) { testLegacyInvalidACNPNoPriority(t) })
		t.Run("Case=LegacyACNPDropEgress", func(t *testing.T) { testLegacyACNPDropEgress(t) })
	})

	// print results for reachability tests
	printResults()
	k8sUtils.LegacyCleanup(namespaces)
}
