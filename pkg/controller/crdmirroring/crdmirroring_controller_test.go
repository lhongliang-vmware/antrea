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

package crdmirroring

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	security "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	fakeversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	legacysecurity "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
	legacyfakeversioned "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned/fake"
	legacycrdinformers "github.com/vmware-tanzu/antrea/pkg/legacyclient/informers/externalversions"
)

const (
	informerDefaultResync = 30 * time.Second
)

type CRDMirroringController struct {
	*Controller
	store       cache.Store
	legacyStore cache.Store
}

var (
	k8sProtocolTCP = corev1.ProtocolTCP
	int1000        = intstr.FromInt(1000)
	p10            = float64(10)
	p11            = float64(11)

	int32For1999 = int32(1999)
	selectorA    = metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB    = metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	allowAction  = security.RuleActionAllow

	alwaysReady = func() bool { return true }
)

func newNetworkPolicyController() (*fakeversioned.Clientset, *legacyfakeversioned.Clientset, *CRDMirroringController) {
	CRDClient := fakeversioned.NewSimpleClientset()
	legacyCRDClient := legacyfakeversioned.NewSimpleClientset()
	CRDInformerFactory := crdinformers.NewSharedInformerFactory(CRDClient, informerDefaultResync)
	legacyCRDInformerFactory := legacycrdinformers.NewSharedInformerFactory(legacyCRDClient, informerDefaultResync)

	networkPolicyController := NewController(
		CRDInformerFactory.Security().V1alpha1().NetworkPolicies(),
		legacyCRDInformerFactory.Security().V1alpha1().NetworkPolicies(),
		CRDClient,
		legacyCRDClient,
		"NetworkPolicy",
	)
	networkPolicyController.listerSycned = alwaysReady
	networkPolicyController.legacyListerSynced = alwaysReady
	return CRDClient, legacyCRDClient, &CRDMirroringController{
		networkPolicyController,
		CRDInformerFactory.Security().V1alpha1().NetworkPolicies().Informer().GetStore(),
		legacyCRDInformerFactory.Security().V1alpha1().NetworkPolicies().Informer().GetStore(),
	}
}

func TestSyncANP(t *testing.T) {
	namespace := "test-namespace"
	name := "testing-name"

	testCases := []struct {
		testName string
		legacy   *legacysecurity.NetworkPolicy
		cur      *security.NetworkPolicy
	}{
		{
			testName: "test ADD with legacy API",
			legacy: &legacysecurity.NetworkPolicy{
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: 10,
					Ingress: []security.Rule{
						{
							Ports: []security.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []security.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			cur: &security.NetworkPolicy{
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []security.Rule{
						{
							Ports: []security.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []security.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
		},
		{
			testName: "test DELETE with legacy API",
			legacy: &legacysecurity.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			cur: &security.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{managedBy: controllerName},
				},
			},
		},
		{
			testName: "test UPDATE with legacy API",
			legacy: &legacysecurity.NetworkPolicy{
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []security.Rule{
						{
							Ports: []security.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []security.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			cur: &security.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{managedBy: controllerName},
				},
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p11,
				},
			},
		},
		{
			testName: "test UPDATE with new API",
			legacy: &legacysecurity.NetworkPolicy{
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p11,
				},
			},
			cur: &security.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{managedBy: controllerName},
				},
				Spec: security.NetworkPolicySpec{
					AppliedTo: []security.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []security.Rule{
						{
							Ports: []security.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []security.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
		},
		{
			testName: "test DELETE with new API",
			legacy: &legacysecurity.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			cur: &security.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{managedBy: controllerName},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			client, legacyClient, controller := newNetworkPolicyController()
			tc.legacy.Name = name
			tc.legacy.Namespace = namespace
			tc.cur.Name = name
			tc.cur.Namespace = namespace

			switch tc.testName {
			case "test ADD with legacy API":
				controller.legacyStore.Add(tc.legacy)
				_, err := legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Create(context.TODO(), tc.legacy, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Expected no error creating legacy NetworkPolicy, got %v", err)
				}

				err = controller.syncCRD(fmt.Sprintf("%s/%s_%s_%s", namespace, name, ADD, new))
				if err != nil {
					t.Fatalf("Running syncCRD got error: %v", err)
				}

				np, err := client.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("Expected no error getting mirrroing NetworkPolicy, got %v", err)
				}
				lnp, err := legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("Expected no error getting mirrroing NetworkPolicy, got %v", err)
				}

				assert.Equal(t, tc.cur.Spec, np.Spec)
				assert.Equal(t, tc.cur.Status, np.Status)
				assert.Equal(t, controllerName, np.GetAnnotations()[managedBy])
				assert.Equal(t, mirrored, lnp.GetAnnotations()[mirrored])
			case "test DELETE with legacy API":
				controller.store.Add(tc.cur)

				_, err := client.SecurityV1alpha1().NetworkPolicies(namespace).Create(context.TODO(), tc.cur, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Expected no error creating NetworkPolicy, got %v", err)
				}

				err = controller.syncCRD(fmt.Sprintf("%s/%s_%s_%s", namespace, name, DELETE, new))
				if err != nil {
					t.Fatalf("Expected no error running syncCRD, got error: %v", err)
				}

				_, err = client.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Fatalf("Expected getting not found mirroring NetworkPolicy, got: %v", err)
				}
			case "test UPDATE with legacy API":
				controller.legacyStore.Add(tc.legacy)
				controller.store.Add(tc.cur)

				_, err := client.SecurityV1alpha1().NetworkPolicies(namespace).Create(context.TODO(), tc.cur, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Expected no error creating mirroring NetworkPolicy, got %v", err)
				}

				err = controller.syncCRD(fmt.Sprintf("%s/%s_%s_%s", namespace, name, UPDATE, new))
				if err != nil {
					t.Fatalf("Expected no error running syncCRD, got error: %v", err)
				}

				np, err := client.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("Expected no error getting mirrored NetworkPolicy, got: %v", err)
				}
				assert.Equal(t, p10, np.Spec.Priority)
				assert.Equal(t, 1, len(np.Spec.Ingress))
				assert.Equal(t, &k8sProtocolTCP, np.Spec.Ingress[0].Ports[0].Protocol)
			case "test UPDATE with new API":
				controller.legacyStore.Add(tc.legacy)
				controller.store.Add(tc.cur)

				_, err := legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Create(context.TODO(), tc.legacy, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Expected no error creating mirroring NetworkPolicy, got %v", err)
				}

				err = controller.syncCRD(fmt.Sprintf("%s/%s_%s_%s", namespace, name, UPDATE, legacy))
				if err != nil {
					t.Fatalf("Expected no error running syncCRD, got error: %v", err)
				}

				np, err := legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("Expected no error getting mirrored NetworkPolicy, got: %v", err)
				}
				assert.Equal(t, p10, np.Spec.Priority)
				assert.Equal(t, 1, len(np.Spec.Ingress))
				assert.Equal(t, &k8sProtocolTCP, np.Spec.Ingress[0].Ports[0].Protocol)
			case "test DELETE with new API":
				controller.legacyStore.Add(tc.legacy)

				_, err := legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Create(context.TODO(), tc.legacy, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Expected no error creating legacy NetworkPolicy, got %v", err)
				}

				err = controller.syncCRD(fmt.Sprintf("%s/%s_%s_%s", namespace, name, DELETE, legacy))
				if err != nil {
					t.Fatalf("Expected no error running syncCRD, got error: %v", err)
				}

				_, err = legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Fatalf("Expected getting not found NetworkPolicy, got: %v", err)
				}
			}
		})
	}
}
