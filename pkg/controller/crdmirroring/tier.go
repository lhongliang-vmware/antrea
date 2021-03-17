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

type TierHandler struct {
	lister       securitylister.TierLister
	legacyLister legacysecuritylister.TierLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewTierHandler(c *Controller) MirroringHandler {
	mc := &TierHandler{
		lister:       c.informer.(securityinformer.TierInformer).Lister(),
		legacyLister: c.legacyInformer.(legacysecurityinformer.TierInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *TierHandler) getNew(namespace, name string) (*security.Tier, error) {
	lister := n.lister
	tier, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return tier, nil
}

func (n *TierHandler) createNew(tier *security.Tier) error {
	client := n.client.SecurityV1alpha1().Tiers()
	_, err := client.Create(context.TODO(), tier, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, tier.Namespace, tier.Name, err)
	}
	return nil
}

// buildNew builds a new Tier with the legacy Tier
func (n *TierHandler) buildNew(ltier *legacysecurity.Tier) *security.Tier {
	tier := &security.Tier{
		Spec: ltier.Spec,
	}
	setMetaData(ltier, tier)
	return tier
}

func (n *TierHandler) updateNew(tier *security.Tier) error {
	client := n.client.SecurityV1alpha1().Tiers()
	_, err := client.Update(context.TODO(), tier, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, tier.Namespace, tier.Name, err)
	}
	return nil
}

func (n *TierHandler) deleteNew(tier *security.Tier) error {
	client := n.client.SecurityV1alpha1().Tiers()
	err := client.Delete(context.TODO(), tier.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, tier.Namespace, tier.Name, err)
	}
	return nil
}

func (n *TierHandler) getLegacy(namespace, name string) (*legacysecurity.Tier, error) {
	lister := n.legacyLister
	tier, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return tier, nil
}

func (n *TierHandler) updateLegacy(ltier *legacysecurity.Tier) error {
	client := n.legacyClient.SecurityV1alpha1().Tiers()
	_, err := client.Update(context.TODO(), ltier, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, ltier.Namespace, ltier.Name, err)
	}
	return nil
}

func (n *TierHandler) deleteLegacy(ltier *legacysecurity.Tier) error {
	client := n.legacyClient.SecurityV1alpha1().Tiers()
	err := client.Delete(context.TODO(), ltier.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, ltier.Namespace, ltier.Name, err)
	}
	return nil
}

// deepEqualTier is used for comparing the legacy and the mirroring new.
func (n *TierHandler) deepEqualTier(ltier *legacysecurity.Tier, tier *security.Tier, namespace, name string) bool {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(ltier.Spec, tier.Spec)
	labels := reflect.DeepEqual(ltier.Labels, tier.Labels)
	if spec && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels
}

// syncData syncs data between the legacy Tier and the mirroring new Tier according to the argument of target.
func (n *TierHandler) syncData(target TARGET, ltier *legacysecurity.Tier, tier *security.Tier) {
	if target == new {
		tier.Spec = ltier.Spec
		tier.Annotations = map[string]string{}
		for label, val := range ltier.Labels {
			tier.Labels[label] = val
		}
	} else if target == legacy {
		ltier.Spec = tier.Spec
		ltier.Annotations = map[string]string{}
		for label, val := range tier.Labels {
			ltier.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target Tier.
func (n *TierHandler) syncSpecAndLabels(target TARGET, ltier *legacysecurity.Tier, tier *security.Tier) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(ltier)
	} else if target == new {
		err = n.updateNew(tier)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *TierHandler) MirroringADD(namespace, name string) error {
	// Get the legacy Tier
	ltier, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new Tier
	err = n.createNew(n.buildNew(ltier))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy Tier by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	// We need to get the latest legacy CRD as the mirroring new CRD may update the legacy CRD.
	ltier, err = n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	setMirroringStatus(ltier, mirrored)
	err = n.updateLegacy(ltier)
	if err != nil {
		return err
	}
	return nil
}

func (n *TierHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy Tier and the mirroring new Tier.
	ltier, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	tier, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new Tier, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new Tier should not be synchronized with legacy Tier.
	if !managedByMirroringController(tier, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new Tier deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new Tier.
	specAndLabels := n.deepEqualTier(ltier, tier, namespace, name)
	if specAndLabels {
		return nil
	}

	n.syncData(target, ltier, tier)
	if !specAndLabels {
		err = n.syncSpecAndLabels(target, ltier, tier)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *TierHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		tier, err := n.getNew(namespace, name)
		if err != nil {
			// If the target Tier we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}
		if !managedByMirroringController(tier, n.CRDName) {
			return nil
		}

		err = n.deleteNew(tier)
		if err != nil {
			return err
		}
	} else if target == legacy {
		ltier, err := n.getLegacy(namespace, name)
		if err != nil {
			// If the target Tier we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}

		err = n.deleteLegacy(ltier)
		if err != nil {
			return err
		}
	}
	return nil
}

// MirroringCHECK checks that if the legacy or new Tier is orphan.
func (n *TierHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy Tier
		_, err := n.getNew(namespace, name)
		if err != nil {
			// If it is not found, delete the new Tier as the legacy Tier that mirroring the new Tier has been deleted.
			if apierrors.IsNotFound(err) {
				err = n.MirroringDELETE(legacy, namespace, name)
				if err != nil {
					return err
				}
				klog.Infof("Found orphan legacy %s %s/%s and deleted it", n.CRDName, namespace, name)
			} else {
				return fmt.Errorf("failed to check mirroring %s %s/%s: %v", n.CRDName, namespace, name, err)
			}
		}
	} else if target == legacy {
		// Get the new Tier
		_, err := n.getLegacy(namespace, name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				err = n.MirroringDELETE(new, namespace, name)
				if err != nil {
					return err
				}
				klog.Infof("Found orphan new %s %s/%s and deleted it", n.CRDName, namespace, name)
			} else {
				return fmt.Errorf("failed to check legacy %s %s/%s: %v", n.CRDName, namespace, name, err)
			}
		}
	}

	return nil
}
