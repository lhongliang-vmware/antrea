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

type ExternalEntityHandler struct {
	lister       corelister.ExternalEntityLister
	legacyLister legacycorelister.ExternalEntityLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewExternalEntityHandler(c *Controller) MirroringHandler {
	mc := &ExternalEntityHandler{
		lister:       c.informer.(coreinformer.ExternalEntityInformer).Lister(),
		legacyLister: c.legacyInformer.(legacycoreinformer.ExternalEntityInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *ExternalEntityHandler) getNew(namespace, name string) (*core.ExternalEntity, error) {
	lister := n.lister.ExternalEntities(namespace)
	ee, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return ee, nil
}

func (n *ExternalEntityHandler) createNew(ee *core.ExternalEntity) error {
	client := n.client.CoreV1alpha2().ExternalEntities(ee.Namespace)
	_, err := client.Create(context.TODO(), ee, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, ee.Namespace, ee.Name, err)
	}
	return nil
}

// buildNew builds a new ExternalEntity with the legacy ExternalEntity
func (n *ExternalEntityHandler) buildNew(lee *legacycore.ExternalEntity) *core.ExternalEntity {
	ee := &core.ExternalEntity{
		Spec: lee.Spec,
	}
	setMetaData(lee, ee)
	return ee
}

func (n *ExternalEntityHandler) updateNew(ee *core.ExternalEntity) error {
	client := n.client.CoreV1alpha2().ExternalEntities(ee.Namespace)
	_, err := client.Update(context.TODO(), ee, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, ee.Namespace, ee.Name, err)
	}
	return nil
}

func (n *ExternalEntityHandler) deleteNew(ee *core.ExternalEntity) error {
	client := n.client.CoreV1alpha2().ExternalEntities(ee.Namespace)
	err := client.Delete(context.TODO(), ee.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, ee.Namespace, ee.Name, err)
	}
	return nil
}

func (n *ExternalEntityHandler) getLegacy(namespace, name string) (*legacycore.ExternalEntity, error) {
	lister := n.legacyLister.ExternalEntities(namespace)
	ee, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return ee, nil
}

func (n *ExternalEntityHandler) updateLegacy(lee *legacycore.ExternalEntity) error {
	client := n.legacyClient.CoreV1alpha2().ExternalEntities(lee.Namespace)
	_, err := client.Update(context.TODO(), lee, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, lee.Namespace, lee.Name, err)
	}
	return nil
}

func (n *ExternalEntityHandler) deleteLegacy(lee *legacycore.ExternalEntity) error {
	client := n.legacyClient.CoreV1alpha2().ExternalEntities(lee.Namespace)
	err := client.Delete(context.TODO(), lee.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, lee.Namespace, lee.Name, err)
	}
	return nil
}

// deepEqualExternalEntity is used for comparing the legacy and the mirroring new.
func (n *ExternalEntityHandler) deepEqualExternalEntity(lee *legacycore.ExternalEntity, ee *core.ExternalEntity, namespace, name string) bool {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(lee.Spec, ee.Spec)
	labels := reflect.DeepEqual(lee.Labels, ee.Labels)
	if spec && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels
}

// syncData syncs data between the legacy ExternalEntity and the mirroring new ExternalEntity according to the argument of target.
func (n *ExternalEntityHandler) syncData(target TARGET, lee *legacycore.ExternalEntity, ee *core.ExternalEntity) {
	if target == new {
		ee.Spec = lee.Spec
		ee.Annotations = map[string]string{}
		for label, val := range lee.Labels {
			ee.Labels[label] = val
		}
	} else if target == legacy {
		lee.Spec = ee.Spec
		lee.Annotations = map[string]string{}
		for label, val := range ee.Labels {
			lee.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target ExternalEntity.
func (n *ExternalEntityHandler) syncSpecAndLabels(target TARGET, lee *legacycore.ExternalEntity, ee *core.ExternalEntity) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(lee)
	} else if target == new {
		err = n.updateNew(ee)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *ExternalEntityHandler) MirroringADD(namespace, name string) error {
	// Get the legacy ExternalEntity
	lee, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new ExternalEntity
	err = n.createNew(n.buildNew(lee))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy ExternalEntity by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	// We need to get the latest legacy CRD as the mirroring new CRD may update the legacy CRD.
	lee, err = n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	setMirroringStatus(lee, mirrored)
	err = n.updateLegacy(lee)
	if err != nil {
		return err
	}
	return nil
}

func (n *ExternalEntityHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy ExternalEntity and the mirroring new ExternalEntity.
	lee, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	ee, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new ExternalEntity, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new ExternalEntity should not be synchronized with legacy ExternalEntity.
	if !managedByMirroringController(ee, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new ExternalEntity deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new ExternalEntity.
	specAndLabels := n.deepEqualExternalEntity(lee, ee, namespace, name)
	if specAndLabels {
		return nil
	}

	n.syncData(target, lee, ee)
	if !specAndLabels {
		err = n.syncSpecAndLabels(target, lee, ee)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *ExternalEntityHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		ee, err := n.getNew(namespace, name)
		if err != nil {
			// If the target ExternalEntity we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}
		if !managedByMirroringController(ee, n.CRDName) {
			return nil
		}

		err = n.deleteNew(ee)
		if err != nil {
			return err
		}
	} else if target == legacy {
		lee, err := n.getLegacy(namespace, name)
		if err != nil {
			// If the target ExternalEntity we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}

		err = n.deleteLegacy(lee)
		if err != nil {
			return err
		}
	}
	return nil
}

// MirroringCHECK checks that if the legacy or new ExternalEntity is orphan.
func (n *ExternalEntityHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy ExternalEntity
		_, err := n.getNew(namespace, name)
		if err != nil {
			// If new is not found, delete the legacy as it is orphan.
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
		// Get the new ExternalEntity
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
