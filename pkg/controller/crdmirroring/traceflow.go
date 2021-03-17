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

	ops "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	opsinformer "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/ops/v1alpha1"
	opslister "github.com/vmware-tanzu/antrea/pkg/client/listers/ops/v1alpha1"
	legacyops "github.com/vmware-tanzu/antrea/pkg/legacyapis/ops/v1alpha1"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacyopsinformer "github.com/vmware-tanzu/antrea/pkg/legacyclient/informers/externalversions/ops/v1alpha1"
	legacyopslister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/ops/v1alpha1"
)

type TraceflowHandler struct {
	lister       opslister.TraceflowLister
	legacyLister legacyopslister.TraceflowLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
	CRDName      string
}

func NewTraceflowHandler(c *Controller) MirroringHandler {
	mc := &TraceflowHandler{
		lister:       c.informer.(opsinformer.TraceflowInformer).Lister(),
		legacyLister: c.legacyInformer.(legacyopsinformer.TraceflowInformer).Lister(),
		client:       c.CRDClient,
		legacyClient: c.legacyCRDClient,
		CRDName:      c.CRDName,
	}
	return mc
}

func (n *TraceflowHandler) getNew(namespace, name string) (*ops.Traceflow, error) {
	lister := n.lister
	tf, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get new %s %s/%s from lister: %v", n.CRDName, namespace, name, err)
	}
	return tf, nil
}

func (n *TraceflowHandler) createNew(tf *ops.Traceflow) error {
	client := n.client.OpsV1alpha1().Traceflows()
	_, err := client.Create(context.TODO(), tf, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to add new %s %s/%s: %v", n.CRDName, tf.Namespace, tf.Name, err)
	}
	return nil
}

// buildNew builds a new Traceflow with the legacy Traceflow
func (n *TraceflowHandler) buildNew(ltf *legacyops.Traceflow) *ops.Traceflow {
	tf := &ops.Traceflow{
		Spec:   ltf.Spec,
		Status: ltf.Status,
	}
	setMetaData(ltf, tf)
	return tf
}

func (n *TraceflowHandler) updateNew(tf *ops.Traceflow) error {
	client := n.client.OpsV1alpha1().Traceflows()
	_, err := client.Update(context.TODO(), tf, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update new %s %s/%s: %v", n.CRDName, tf.Namespace, tf.Name, err)
	}
	return nil
}

func (n *TraceflowHandler) updateStatusNew(tf *ops.Traceflow) error {
	client := n.client.OpsV1alpha1().Traceflows()
	_, err := client.UpdateStatus(context.TODO(), tf, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of new %s %s/%s : %v", n.CRDName, tf.Namespace, tf.Name, err)
	}
	return nil
}

func (n *TraceflowHandler) deleteNew(tf *ops.Traceflow) error {
	client := n.client.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), tf.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete new %s %s/%s: %v", n.CRDName, tf.Namespace, tf.Name, err)
	}
	return nil
}

func (n *TraceflowHandler) getLegacy(namespace, name string) (*legacyops.Traceflow, error) {
	lister := n.legacyLister
	tf, err := lister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get legacy %s %s/%s from listers: %v", n.CRDName, namespace, name, err)
	}
	return tf, nil
}

func (n *TraceflowHandler) updateLegacy(ltf *legacyops.Traceflow) error {
	client := n.legacyClient.OpsV1alpha1().Traceflows()
	_, err := client.Update(context.TODO(), ltf, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update legacy %s %s/%s: %v", n.CRDName, ltf.Namespace, ltf.Name, err)
	}
	return nil
}

func (n *TraceflowHandler) updateStatusLegacy(ltf *legacyops.Traceflow) error {
	client := n.legacyClient.OpsV1alpha1().Traceflows()
	_, err := client.UpdateStatus(context.TODO(), ltf, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of legacy %s %s/%s: %v", n.CRDName, ltf.Namespace, ltf.Name, err)
	}
	return nil
}

func (n *TraceflowHandler) deleteLegacy(ltf *legacyops.Traceflow) error {
	client := n.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies()
	err := client.Delete(context.TODO(), ltf.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete legacy %s %s/%s: %v", n.CRDName, ltf.Namespace, ltf.Name, err)
	}
	return nil
}

// deepEqualTraceflow is used for comparing the legacy and the mirroring new.
func (n *TraceflowHandler) deepEqualTraceflow(ltf *legacyops.Traceflow, tf *ops.Traceflow, namespace, name string) (bool, bool) {
	// This is used to stop cycle UPDATE event between legacy CRD and new CRD.
	spec := reflect.DeepEqual(ltf.Spec, tf.Spec)
	status := reflect.DeepEqual(ltf.Status, tf.Status)
	labels := reflect.DeepEqual(ltf.Labels, tf.Labels)
	if spec && status && labels {
		klog.Infof("%s %s/%s is synced, revoke mirroring", n.CRDName, namespace, name)
	}
	return spec && labels, status
}

// syncData syncs data between the legacy Traceflow and the mirroring new Traceflow according to the argument of target.
func (n *TraceflowHandler) syncData(target TARGET, ltf *legacyops.Traceflow, tf *ops.Traceflow) {
	if target == new {
		tf.Status = ltf.Status
		tf.Spec = ltf.Spec
		tf.Annotations = map[string]string{}
		for label, val := range ltf.Labels {
			tf.Labels[label] = val
		}
	} else if target == legacy {
		ltf.Status = tf.Status
		ltf.Spec = tf.Spec
		ltf.Annotations = map[string]string{}
		for label, val := range tf.Labels {
			ltf.Labels[label] = val
		}
	}
}

// syncSpecAndLabels updates the Spec and Labels of target Traceflow.
func (n *TraceflowHandler) syncSpecAndLabels(target TARGET, ltf *legacyops.Traceflow, tf *ops.Traceflow) error {
	var err error
	if target == legacy {
		err = n.updateLegacy(ltf)
	} else if target == new {
		err = n.updateNew(tf)
	}
	if err != nil {
		return err
	}
	return nil
}

// syncStatus updates the Status of target Traceflow.
func (n *TraceflowHandler) syncStatus(target TARGET, ltf *legacyops.Traceflow, tf *ops.Traceflow) error {
	var err error
	if target == legacy {
		err = n.updateStatusLegacy(ltf)
	} else if target == new {
		err = n.updateStatusNew(tf)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *TraceflowHandler) MirroringADD(namespace, name string) error {
	// Get the legacy Traceflow
	ltf, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}

	// Create a mirroring new Traceflow
	err = n.createNew(n.buildNew(ltf))
	if err != nil {
		return err
	}

	// Update the mirroring status of legacy Traceflow by setting annotation.
	// Add a key-value "mirroringStatus/mirrored" to annotation.
	// We need to get the latest legacy CRD as the mirroring new CRD may update the legacy CRD.
	ltf, err = n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	setMirroringStatus(ltf, mirrored)
	err = n.updateLegacy(ltf)
	if err != nil {
		return err
	}
	return nil
}

func (n *TraceflowHandler) MirroringUPDATE(target TARGET, namespace, name string) error {
	// Get the legacy Traceflow and the mirroring new Traceflow.
	ltf, err := n.getLegacy(namespace, name)
	if err != nil {
		return err
	}
	tf, err := n.getNew(namespace, name)
	if err != nil {
		return err
	}

	// One possible case is that before removing the annotation of "managedBy":"crdmirroring-controller" from mirroring
	// new Traceflow, an UPDATE event has been triggered and sent a key to CRD mirroring controller worker queue.
	// However, util the annotation of "managedBy":"crdmirroring-controller" is removed, the key of UPDATE event is not
	// processed by worker function. Since the annotation of "managedBy":"crdmirroring-controller is  removed, the
	// mirroring new Traceflow should not be synchronized with legacy Traceflow.
	if !managedByMirroringController(tf, n.CRDName) {
		return nil
	}

	// If Spec, Labels, Status of the legacy and the mirroring new Traceflow deep equals, stop updating.
	// This is used for stopping cycle updating between the legacy and the mirroring new Traceflow.
	specAndLabels, status := n.deepEqualTraceflow(ltf, tf, namespace, name)
	if specAndLabels && status {
		return nil
	}

	n.syncData(target, ltf, tf)
	if !specAndLabels {
		err = n.syncSpecAndLabels(target, ltf, tf)
		if err != nil {
			return err
		}
	}
	if !status {
		err = n.syncStatus(target, ltf, tf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *TraceflowHandler) MirroringDELETE(target TARGET, namespace, name string) error {
	if target == new {
		tf, err := n.getNew(namespace, name)
		if err != nil {
			// If the target Traceflow we want to delete is not found, just return nil.
			if apierrors.IsNotFound(err) {
				return nil
			} else {
				return err
			}
		}
		if !managedByMirroringController(tf, n.CRDName) {
			return nil
		}

		err = n.deleteNew(tf)
		if err != nil {
			return err
		}
	} else if target == legacy {
		lnp, err := n.getLegacy(namespace, name)
		if err != nil {
			// If the target Traceflow we want to delete is not found, just return nil.
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

// MirroringCHECK checks that if the legacy or new Traceflow is orphan.
func (n *TraceflowHandler) MirroringCHECK(target TARGET, namespace, name string) error {
	if target == new {
		// Get the legacy Traceflow
		_, err := n.getNew(namespace, name)
		if err != nil {
			// If it is not found, delete the new Traceflow as the legacy Traceflow that mirroring the new Traceflow has been deleted.
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
		// Get the new Traceflow
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
