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
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	security "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	securityinformer "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/security/v1alpha1"
	securitylister "github.com/vmware-tanzu/antrea/pkg/client/listers/security/v1alpha1"
	legacysecurity "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacysecurityinformer "github.com/vmware-tanzu/antrea/pkg/legacyclient/informers/externalversions/security/v1alpha1"
	legacysecuritylister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/security/v1alpha1"
)

type NetworkPolicyHandler struct {
	lister       securitylister.NetworkPolicyLister
	legacyLister legacysecuritylister.NetworkPolicyLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewNetworkPolicyHandler(c *Controller) MirroringHandler {
	mc := &NetworkPolicyHandler{
		lister:       c.informer.(securityinformer.NetworkPolicyInformer).Lister(),
		legacyLister: c.legacyInformer.(legacysecurityinformer.NetworkPolicyInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *NetworkPolicyHandler) getNew(namespace, name string) (*security.NetworkPolicy, error) {
	lister := n.lister.NetworkPolicies(namespace)
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *NetworkPolicyHandler) createNew(np *security.NetworkPolicy) error {
	client := n.client.SecurityV1alpha1().NetworkPolicies(np.Namespace)
	_, err := client.Create(context.TODO(), np, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, np.Namespace, np.Name, err)
	}
	return nil
}

// buildNew builds a new NetworkPolicy with the legacy NetworkPolicy
func (n *NetworkPolicyHandler) buildNew(lnp *legacysecurity.NetworkPolicy) *security.NetworkPolicy {
	np := &security.NetworkPolicy{
		Spec:   lnp.Spec,
		Status: lnp.Status,
	}
	setMetaData(lnp, np)
	return np
}

func (n *NetworkPolicyHandler) updateNew(np *security.NetworkPolicy) error {
	client := n.client.SecurityV1alpha1().NetworkPolicies(np.Namespace)
	_, err := client.Update(context.TODO(), np, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, np.Namespace, np.Name, err)
	}
	return nil
}

func (n *NetworkPolicyHandler) updateStatusNew(np *security.NetworkPolicy) error {
	client := n.client.SecurityV1alpha1().NetworkPolicies(np.Namespace)
	_, err := client.UpdateStatus(context.TODO(), np, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of new %s %s/%s : %v", n.CRDName, np.Namespace, np.Name, err)
	}
	return nil
}

func (n *NetworkPolicyHandler) deleteNew(np *security.NetworkPolicy) error {
	client := n.client.SecurityV1alpha1().NetworkPolicies(np.Namespace)
	err := client.Delete(context.TODO(), np.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, np.Namespace, np.Name, err)
	}
	return nil
}

func (n *NetworkPolicyHandler) getLegacy(namespace, name string) (*legacysecurity.NetworkPolicy, error) {
	lister := n.legacyLister.NetworkPolicies(namespace)
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *NetworkPolicyHandler) updateLegacy(lnp *legacysecurity.NetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().NetworkPolicies(lnp.Namespace)
	_, err := client.Update(context.TODO(), lnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, lnp.Namespace, lnp.Name, err)
	}
	return nil
}

func (n *NetworkPolicyHandler) updateStatusLegacy(lnp *legacysecurity.NetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().NetworkPolicies(lnp.Namespace)
	_, err := client.UpdateStatus(context.TODO(), lnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of legacy %s %s/%s: %v", n.CRDName, lnp.Namespace, lnp.Name, err)
	}
	return nil
}

func (n *NetworkPolicyHandler) deleteLegacy(lnp *legacysecurity.NetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().NetworkPolicies(lnp.Namespace)
	err := client.Delete(context.TODO(), lnp.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, lnp.Namespace, lnp.Name, err)
	}
	return nil
}

// deepEqualNetworkPolicy is used for comparing the legacy and the mirroring new.
func (n *NetworkPolicyHandler) deepEqualNetworkPolicy(lnp *legacysecurity.NetworkPolicy, np *security.NetworkPolicy, namespace, name string) (bool, bool) {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(lnp.Spec, np.Spec)
	status := reflect.DeepEqual(lnp.Status, np.Status)
	labels := reflect.DeepEqual(lnp.Labels, np.Labels)
	if spec && status && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels, status
}

// syncData syncs data between the legacy NetworkPolicy and the mirroring new NetworkPolicy according to the argument of target.
func (n *NetworkPolicyHandler) syncData(target TARGET, lnp *legacysecurity.NetworkPolicy, np *security.NetworkPolicy) {
	if target == new {
		np.Status = lnp.Status
		np.Spec = lnp.Spec
		np.Annotations = map[string]string{}
		for label, val := range lnp.Labels {
			np.Labels[label] = val
		}
	} else if target == legacy {
		lnp.Status = np.Status
		lnp.Spec = np.Spec
		lnp.Annotations = map[string]string{}
		for label, val := range np.Labels {
			lnp.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target NetworkPolicy.
func (n *NetworkPolicyHandler) syncSpecAndLabels(target TARGET, lnp *legacysecurity.NetworkPolicy, np *security.NetworkPolicy) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(lnp)
	} else if target == new {
		err = n.updateNew(np)
	}
	if err != nil {
		return err
	}
	return nil
}

// syncStatus updates the Status of target NetworkPolicy.
func (n *NetworkPolicyHandler) syncStatus(target TARGET, lnp *legacysecurity.NetworkPolicy, np *security.NetworkPolicy) error {
	var err error
	if target == legacy {
		err = n.updateStatusLegacy(lnp)
	} else if target == new {
		err = n.updateStatusNew(np)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *NetworkPolicyHandler) MirroringADD(namespace, name string) error {
	// Get the legacy NetworkPolicy
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new NetworkPolicy
	err = n.createNew(n.buildNew(lnp))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy NetworkPolicy by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	setMirroringStatus(lnp, mirrored)
	err = n.updateLegacy(lnp)
	if err != nil {
		return err
	}
	return nil
}

func (n *NetworkPolicyHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy NetworkPolicy and the mirroring new NetworkPolicy.
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	np, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new NetworkPolicy, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new NetworkPolicy should not be synchronized with legacy NetworkPolicy.
	if !managedByMirroringController(np, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new NetworkPolicy deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new NetworkPolicy.
	specAndLabels, status := n.deepEqualNetworkPolicy(lnp, np, namespace, name)
	if specAndLabels && status {
		return nil
	}

	n.syncData(target, lnp, np)
	if !specAndLabels {
		err = n.syncSpecAndLabels(target, lnp, np)
		if err != nil {
			return err
		}
	}
	if !status {
		err = n.syncStatus(target, lnp, np)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *NetworkPolicyHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		np, err := n.getNew(namespace, name)
		if err != nil {
			// If the target NetworkPolicy we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}
		if !managedByMirroringController(np, n.CRDName) {
			return nil
		}

		err = n.deleteNew(np)
		if err != nil {
			return err
		}
	} else if target == legacy {
		lnp, err := n.getLegacy(namespace, name)
		if err != nil {
			// If the target NetworkPolicy we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}

		err = n.deleteLegacy(lnp)
		if err != nil {
			return err
		}
	}
	return nil
}

// MirroringCHECK checks that if the legacy or new NetworkPolicy is orphan.
func (n *NetworkPolicyHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy NetworkPolicy
		_, err := n.getLegacy(namespace, name)
		if err != nil {
			// If it is not found, delete the new NetworkPolicy as the legacy NetworkPolicy that mirroring the new NetworkPolicy has been deleted.
			if apierrors.IsNotFound(err) {
				err = n.MirroringDELETE(new, namespace, name)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("failed to check mirroring %s %s/%s: %v", n.CRDName, namespace, name, err)
			}
		}
	} else if target == legacy {
		// Get the new NetworkPolicy
		_, err := n.getNew(namespace, name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				err = n.MirroringDELETE(legacy, namespace, name)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("failed to check legacy %s %s/%s: %v", n.CRDName, namespace, name, err)
			}
		}
	}

	return nil
}
