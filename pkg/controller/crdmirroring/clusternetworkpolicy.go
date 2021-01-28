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

type ClusterNetworkPolicyHandler struct {
	lister       securitylister.ClusterNetworkPolicyLister
	legacyLister legacysecuritylister.ClusterNetworkPolicyLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewClusterNetworkPolicyHandler(c *Controller) MirroringHandler {
	mc := &ClusterNetworkPolicyHandler{
		lister:       c.informer.(securityinformer.ClusterNetworkPolicyInformer).Lister(),
		legacyLister: c.legacyInformer.(legacysecurityinformer.ClusterNetworkPolicyInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *ClusterNetworkPolicyHandler) getNew(namespace, name string) (*security.ClusterNetworkPolicy, error) {
	lister := n.lister
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *ClusterNetworkPolicyHandler) createNew(cnp *security.ClusterNetworkPolicy) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	_, err := client.Create(context.TODO(), cnp, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, cnp.Namespace, cnp.Name, err)
	}
	return nil
}

// buildNew builds a new ClusterNetworkPolicy with the legacy ClusterNetworkPolicy
func (n *ClusterNetworkPolicyHandler) buildNew(lcnp *legacysecurity.ClusterNetworkPolicy) *security.ClusterNetworkPolicy {
	cnp := &security.ClusterNetworkPolicy{
		Spec:   lcnp.Spec,
		Status: lcnp.Status,
	}
	setMetaData(lcnp, cnp)
	return cnp
}

func (n *ClusterNetworkPolicyHandler) updateNew(cnp *security.ClusterNetworkPolicy) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	_, err := client.Update(context.TODO(), cnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, cnp.Namespace, cnp.Name, err)
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) updateStatusNew(cnp *security.ClusterNetworkPolicy) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	_, err := client.UpdateStatus(context.TODO(), cnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of new %s %s/%s : %v", n.CRDName, cnp.Namespace, cnp.Name, err)
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) deleteNew(cnp *security.ClusterNetworkPolicy) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), cnp.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, cnp.Namespace, cnp.Name, err)
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) getLegacy(namespace, name string) (*legacysecurity.ClusterNetworkPolicy, error) {
	lister := n.legacyLister
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *ClusterNetworkPolicyHandler) updateLegacy(lcnp *legacysecurity.ClusterNetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies()
	_, err := client.Update(context.TODO(), lcnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, lcnp.Namespace, lcnp.Name, err)
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) updateStatusLegacy(lcnp *legacysecurity.ClusterNetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies()
	_, err := client.UpdateStatus(context.TODO(), lcnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of legacy %s %s/%s: %v", n.CRDName, lcnp.Namespace, lcnp.Name, err)
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) deleteLegacy(lcnp *legacysecurity.ClusterNetworkPolicy) error {
	client := n.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), lcnp.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, lcnp.Namespace, lcnp.Name, err)
	}
	return nil
}

// deepEqualClusterNetworkPolicy is used for comparing the legacy and the mirroring new.
func (n *ClusterNetworkPolicyHandler) deepEqualClusterNetworkPolicy(lcnp *legacysecurity.ClusterNetworkPolicy, cnp *security.ClusterNetworkPolicy, namespace, name string) (bool, bool) {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(lcnp.Spec, cnp.Spec)
	status := reflect.DeepEqual(lcnp.Status, cnp.Status)
	labels := reflect.DeepEqual(lcnp.Labels, cnp.Labels)
	if spec && status && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels, status
}

// syncData syncs data between the legacy ClusterNetworkPolicy and the mirroring new ClusterNetworkPolicy according to the argument of target.
func (n *ClusterNetworkPolicyHandler) syncData(target TARGET, lcnp *legacysecurity.ClusterNetworkPolicy, cnp *security.ClusterNetworkPolicy) {
	if target == new {
		cnp.Status = lcnp.Status
		cnp.Spec = lcnp.Spec
		cnp.Annotations = map[string]string{}
		for label, val := range lcnp.Labels {
			cnp.Labels[label] = val
		}
	} else if target == legacy {
		lcnp.Status = cnp.Status
		lcnp.Spec = cnp.Spec
		lcnp.Annotations = map[string]string{}
		for label, val := range cnp.Labels {
			lcnp.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target ClusterNetworkPolicy.
func (n *ClusterNetworkPolicyHandler) syncSpecAndLabels(target TARGET, lcnp *legacysecurity.ClusterNetworkPolicy, cnp *security.ClusterNetworkPolicy) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(lcnp)
	} else if target == new {
		err = n.updateNew(cnp)
	}
	if err != nil {
		return err
	}
	return nil
}

// syncStatus updates the Status of target ClusterNetworkPolicy.
func (n *ClusterNetworkPolicyHandler) syncStatus(target TARGET, lcnp *legacysecurity.ClusterNetworkPolicy, cnp *security.ClusterNetworkPolicy) error {
	var err error
	if target == legacy {
		err = n.updateStatusLegacy(lcnp)
	} else if target == new {
		err = n.updateStatusNew(cnp)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) MirroringADD(namespace, name string) error {
	// Get the legacy ClusterNetworkPolicy
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new ClusterNetworkPolicy
	err = n.createNew(n.buildNew(lnp))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy ClusterNetworkPolicy by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	setMirroringStatus(lnp, mirrored)
	err = n.updateLegacy(lnp)
	if err != nil {
		return err
	}
	return nil
}

func (n *ClusterNetworkPolicyHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy ClusterNetworkPolicy and the mirroring new ClusterNetworkPolicy.
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	np, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new ClusterNetworkPolicy, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new ClusterNetworkPolicy should not be synchronized with legacy ClusterNetworkPolicy.
	if !managedByMirroringController(np, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new ClusterNetworkPolicy deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new ClusterNetworkPolicy.
	specAndLabels, status := n.deepEqualClusterNetworkPolicy(lnp, np, namespace, name)
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

func (n *ClusterNetworkPolicyHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		np, err := n.getNew(namespace, name)
		if err != nil {
			// If the target ClusterNetworkPolicy we want to delete is not found, just return nil.
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
			// If the target ClusterNetworkPolicy we want to delete is not found, just return nil.
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

// MirroringCHECK checks that if the legacy or new ClusterNetworkPolicy is orphan.
func (n *ClusterNetworkPolicyHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy ClusterNetworkPolicy
		_, err := n.getLegacy(namespace, name)
		if err != nil {
			// If it is not found, delete the new ClusterNetworkPolicy as the legacy ClusterNetworkPolicy that mirroring the new ClusterNetworkPolicy has been deleted.
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
		// Get the new ClusterNetworkPolicy
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
