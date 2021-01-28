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
	"fmt"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"

	core "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	ops "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	security "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	legacycore "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacyops "github.com/vmware-tanzu/antrea/pkg/legacyapis/ops/v1alpha1"
	legacysecurity "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
)

func (c *Controller) onNewCRDAdd(obj interface{}) {
	var CRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		CRD = obj.(*security.NetworkPolicy)
	case ClusterNetworkPolicy:
		CRD = obj.(*security.ClusterNetworkPolicy)
	case Tier:
		CRD = obj.(*security.Tier)
	case ClusterGroup:
		CRD = obj.(*core.ClusterGroup)
	case ExternalEntity:
		CRD = obj.(*core.ExternalEntity)
	case Traceflow:
		CRD = obj.(*ops.Traceflow)
	}
	if CRD == nil {
		utilruntime.HandleError(fmt.Errorf("onNewCRDAdd() got unexpected type: %T", obj))
		return
	}

	// Check if the legacy CRD mirroring current CRD exists.
	if CRD.GetAnnotations()[managedBy] == controllerName {
		klog.Infof("Processing mirroring %s %s/%s CHECK event", c.CRDName, CRD.GetNamespace(), CRD.GetName())
		c.queueMirroringInfo(obj, CHECK, new)
	}
}

func (c *Controller) onNewCRDUpdate(prevObj, obj interface{}) {
	var CRD, prevCRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		CRD = obj.(*security.NetworkPolicy)
		prevCRD = obj.(*security.NetworkPolicy)
	case ClusterNetworkPolicy:
		CRD = obj.(*security.ClusterNetworkPolicy)
		prevCRD = obj.(*security.ClusterNetworkPolicy)
	case Tier:
		CRD = obj.(*security.Tier)
		prevCRD = obj.(*security.Tier)
	case ClusterGroup:
		CRD = obj.(*core.ClusterGroup)
		prevCRD = obj.(*core.ClusterGroup)
	case ExternalEntity:
		CRD = obj.(*core.ExternalEntity)
		prevCRD = obj.(*core.ExternalEntity)
	case Traceflow:
		CRD = obj.(*ops.Traceflow)
		prevCRD = obj.(*ops.Traceflow)
	}

	if CRD == nil || prevCRD == nil {
		utilruntime.HandleError(fmt.Errorf("onNewCRDUpdate() got unexpected type: %T, %T", prevObj, obj))
		return
	}

	if CRD.GetAnnotations()[managedBy] == controllerName && prevCRD.GetAnnotations()[managedBy] == controllerName {
		klog.Infof("Processing mirroring %s %s/%s UPDATE event", c.CRDName, CRD.GetNamespace(), CRD.GetName())
		c.queueMirroringInfo(obj, UPDATE, legacy)
	}
}

func (c *Controller) onNewCRDDelete(obj interface{}) {
	var CRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		CRD = getCRDFromDeleteAction(obj).(*security.NetworkPolicy)
	case ClusterNetworkPolicy:
		CRD = getCRDFromDeleteAction(obj).(*security.ClusterNetworkPolicy)
	case Tier:
		CRD = getCRDFromDeleteAction(obj).(*security.Tier)
	case ClusterGroup:
		CRD = getCRDFromDeleteAction(obj).(*core.ClusterGroup)
	case ExternalEntity:
		CRD = getCRDFromDeleteAction(obj).(*core.ExternalEntity)
	case Traceflow:
		CRD = getCRDFromDeleteAction(obj).(*ops.Traceflow)
	}
	if CRD == nil {
		utilruntime.HandleError(fmt.Errorf("onNewCRDDelete() got unexpected type: %T", obj))
		return
	}

	if CRD.GetAnnotations()[managedBy] == controllerName {
		klog.Infof("Processing mirroring %s %s/%s DELETE event", c.CRDName, CRD.GetNamespace(), CRD.GetName())
		c.queueMirroringInfo(obj, DELETE, legacy)
		return
	}
}

func (c *Controller) onLegacyCRDAdd(obj interface{}) {
	var legacyCRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		legacyCRD = obj.(*legacysecurity.NetworkPolicy)
	case ClusterNetworkPolicy:
		legacyCRD = obj.(*legacysecurity.ClusterNetworkPolicy)
	case Tier:
		legacyCRD = obj.(*legacysecurity.Tier)
	case ClusterGroup:
		legacyCRD = obj.(*legacycore.ClusterGroup)
	case ExternalEntity:
		legacyCRD = obj.(*legacycore.ExternalEntity)
	case Traceflow:
		legacyCRD = obj.(*legacyops.Traceflow)
	}
	if legacyCRD == nil {
		utilruntime.HandleError(fmt.Errorf("onLegacyCRDAdd() got unexpected type: %T", obj))
		return
	}

	if legacyCRD.GetAnnotations()[mirroringStatus] == mirrored {
		klog.Infof("Processing legacy %s %s/%s CHECK event", c.CRDName, legacyCRD.GetNamespace(), legacyCRD.GetName())
		c.queueMirroringInfo(obj, CHECK, legacy)
		return
	}

	klog.Infof("Processing legacy %s %s/%s ADD event", c.CRDName, legacyCRD.GetNamespace(), legacyCRD.GetName())
	c.queueMirroringInfo(obj, ADD, new)
}

func (c *Controller) onLegacyCRDUpdate(prevObj, obj interface{}) {
	var legacyCRD, legacyPrevCRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		legacyCRD = obj.(*legacysecurity.NetworkPolicy)
		legacyPrevCRD = obj.(*legacysecurity.NetworkPolicy)
	case ClusterNetworkPolicy:
		legacyCRD = obj.(*legacysecurity.ClusterNetworkPolicy)
		legacyPrevCRD = obj.(*legacysecurity.ClusterNetworkPolicy)
	case Tier:
		legacyCRD = obj.(*legacysecurity.Tier)
		legacyPrevCRD = obj.(*legacysecurity.Tier)
	case ClusterGroup:
		legacyCRD = obj.(*legacycore.ClusterGroup)
		legacyPrevCRD = obj.(*legacycore.ClusterGroup)
	case ExternalEntity:
		legacyCRD = obj.(*legacycore.ExternalEntity)
		legacyPrevCRD = obj.(*legacycore.ExternalEntity)
	case Traceflow:
		legacyCRD = obj.(*legacyops.Traceflow)
		legacyPrevCRD = obj.(*legacyops.Traceflow)
	}
	if legacyCRD == nil || legacyPrevCRD == nil {
		utilruntime.HandleError(fmt.Errorf("onLegacyCRDUpdate() got unexpected type: %T, %T", prevObj, obj))
		return
	}

	klog.Infof("Processing legacy %s %s/%s UPDATE event", c.CRDName, legacyCRD.GetNamespace(), legacyCRD.GetName())
	c.queueMirroringInfo(obj, UPDATE, new)

}

func (c *Controller) onLegacyCRDDelete(obj interface{}) {
	var legacyCRD GenericCRD
	switch c.CRDName {
	case NetworkPolicy:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacysecurity.NetworkPolicy)
	case ClusterNetworkPolicy:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacysecurity.ClusterNetworkPolicy)
	case Tier:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacysecurity.Tier)
	case ClusterGroup:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacycore.ClusterGroup)
	case ExternalEntity:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacycore.ExternalEntity)
	case Traceflow:
		legacyCRD = getLegacyCRDFromDeleteAction(obj).(*legacyops.Traceflow)
	}
	if legacyCRD == nil {
		utilruntime.HandleError(fmt.Errorf("onLegacyCRDAdd() got unexpected type: %T", obj))
		return
	}

	klog.Infof("Processing legacy %s %s/%s DELETE event", c.CRDName, legacyCRD.GetNamespace(), legacyCRD.GetName())
	c.queueMirroringInfo(obj, DELETE, new)
}
