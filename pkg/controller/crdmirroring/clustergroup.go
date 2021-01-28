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

	core "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	coreinformer "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/core/v1alpha2"
	corelister "github.com/vmware-tanzu/antrea/pkg/client/listers/core/v1alpha2"
	legacycore "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacycoreinformer "github.com/vmware-tanzu/antrea/pkg/legacyclient/informers/externalversions/core/v1alpha2"
	legacycorelister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/core/v1alpha2"
)

type ClusterGroupHandler struct {
	lister       corelister.ClusterGroupLister
	legacyLister legacycorelister.ClusterGroupLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewClusterGroupHandler(c *Controller) MirroringHandler {
	mc := &ClusterGroupHandler{
		lister:       c.informer.(coreinformer.ClusterGroupInformer).Lister(),
		legacyLister: c.legacyInformer.(legacycoreinformer.ClusterGroupInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *ClusterGroupHandler) getNew(namespace, name string) (*core.ClusterGroup, error) {
	lister := n.lister
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *ClusterGroupHandler) createNew(cg *core.ClusterGroup) error {
	client := n.client.CoreV1alpha2().ClusterGroups()
	_, err := client.Create(context.TODO(), cg, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, cg.Namespace, cg.Name, err)
	}
	return nil
}

// buildNew builds a new ClusterGroup with the legacy ClusterGroup
func (n *ClusterGroupHandler) buildNew(lcg *legacycore.ClusterGroup) *core.ClusterGroup {
	cg := &core.ClusterGroup{
		Spec:   lcg.Spec,
		Status: lcg.Status,
	}
	setMetaData(lcg, cg)
	return cg
}

func (n *ClusterGroupHandler) updateNew(cg *core.ClusterGroup) error {
	client := n.client.CoreV1alpha2().ClusterGroups()
	_, err := client.Update(context.TODO(), cg, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, cg.Namespace, cg.Name, err)
	}
	return nil
}

func (n *ClusterGroupHandler) updateStatusNew(cg *core.ClusterGroup) error {
	client := n.client.CoreV1alpha2().ClusterGroups()
	_, err := client.UpdateStatus(context.TODO(), cg, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of new %s %s/%s : %v", n.CRDName, cg.Namespace, cg.Name, err)
	}
	return nil
}

func (n *ClusterGroupHandler) deleteNew(cg *core.ClusterGroup) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), cg.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, cg.Namespace, cg.Name, err)
	}
	return nil
}

func (n *ClusterGroupHandler) getLegacy(namespace, name string) (*legacycore.ClusterGroup, error) {
	lister := n.legacyLister
	np, err := lister.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return np, nil
}

func (n *ClusterGroupHandler) updateLegacy(lcg *legacycore.ClusterGroup) error {
	client := n.legacyClient.CoreV1alpha2().ClusterGroups()
	_, err := client.Update(context.TODO(), lcg, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, lcg.Namespace, lcg.Name, err)
	}
	return nil
}

func (n *ClusterGroupHandler) updateStatusLegacy(lcg *legacycore.ClusterGroup) error {
	client := n.legacyClient.CoreV1alpha2().ClusterGroups()
	_, err := client.UpdateStatus(context.TODO(), lcg, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of legacy %s %s/%s: %v", n.CRDName, lcg.Namespace, lcg.Name, err)
	}
	return nil
}

func (n *ClusterGroupHandler) deleteLegacy(lcg *legacycore.ClusterGroup) error {
	client := n.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), lcg.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, lcg.Namespace, lcg.Name, err)
	}
	return nil
}

// deepEqualClusterGroup is used for comparing the legacy and the mirroring new.
func (n *ClusterGroupHandler) deepEqualClusterGroup(lcg *legacycore.ClusterGroup, cg *core.ClusterGroup, namespace, name string) (bool, bool) {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(lcg.Spec, cg.Spec)
	status := reflect.DeepEqual(lcg.Status, cg.Status)
	labels := reflect.DeepEqual(lcg.Labels, cg.Labels)
	if spec && status && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels, status
}

// syncData syncs data between the legacy ClusterGroup and the mirroring new ClusterGroup according to the argument of target.
func (n *ClusterGroupHandler) syncData(target TARGET, lcg *legacycore.ClusterGroup, cg *core.ClusterGroup) {
	if target == new {
		cg.Status = lcg.Status
		cg.Spec = lcg.Spec
		cg.Annotations = map[string]string{}
		for label, val := range lcg.Labels {
			cg.Labels[label] = val
		}
	} else if target == legacy {
		lcg.Status = cg.Status
		lcg.Spec = cg.Spec
		lcg.Annotations = map[string]string{}
		for label, val := range cg.Labels {
			lcg.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target ClusterGroup.
func (n *ClusterGroupHandler) syncSpecAndLabels(target TARGET, lcg *legacycore.ClusterGroup, cg *core.ClusterGroup) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(lcg)
	} else if target == new {
		err = n.updateNew(cg)
	}
	if err != nil {
		return err
	}
	return nil
}

// syncStatus updates the Status of target ClusterGroup.
func (n *ClusterGroupHandler) syncStatus(target TARGET, lcg *legacycore.ClusterGroup, cg *core.ClusterGroup) error {
	var err error
	if target == legacy {
		err = n.updateStatusLegacy(lcg)
	} else if target == new {
		err = n.updateStatusNew(cg)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *ClusterGroupHandler) MirroringADD(namespace, name string) error {
	// Get the legacy ClusterGroup
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new ClusterGroup
	err = n.createNew(n.buildNew(lnp))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy ClusterGroup by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	setMirroringStatus(lnp, mirrored)
	err = n.updateLegacy(lnp)
	if err != nil {
		return err
	}
	return nil
}

func (n *ClusterGroupHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy ClusterGroup and the mirroring new ClusterGroup.
	lnp, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	np, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new ClusterGroup, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new ClusterGroup should not be synchronized with legacy ClusterGroup.
	if !managedByMirroringController(np, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new ClusterGroup deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new ClusterGroup.
	specAndLabels, status := n.deepEqualClusterGroup(lnp, np, namespace, name)
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

func (n *ClusterGroupHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		np, err := n.getNew(namespace, name)
		if err != nil {
			// If the target ClusterGroup we want to delete is not found, just return nil.
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
			// If the target ClusterGroup we want to delete is not found, just return nil.
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

// MirroringCHECK checks that if the legacy or new ClusterGroup is orphan.
func (n *ClusterGroupHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy ClusterGroup
		_, err := n.getLegacy(namespace, name)
		if err != nil {
			// If it is not found, delete the new ClusterGroup as the legacy ClusterGroup that mirroring the new ClusterGroup has been deleted.
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
		// Get the new ClusterGroup
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
