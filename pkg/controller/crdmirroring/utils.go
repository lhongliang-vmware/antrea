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
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	core "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	ops "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	security "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	legacycore "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacyops "github.com/vmware-tanzu/antrea/pkg/legacyapis/ops/v1alpha1"
	legacysecurity "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
)

func setMirroringStatus(CRD GenericCRD, status string) {
	if CRD.GetAnnotations() == nil {
		CRD.SetAnnotations(map[string]string{})
	}
	CRD.GetAnnotations()[mirroringStatus] = status
}

func setMetaData(legacy, new GenericCRD) {
	new.SetLabels(legacy.GetLabels())
	new.SetName(legacy.GetName())
	new.SetNamespace(legacy.GetNamespace())
	new.SetAnnotations(map[string]string{managedBy: controllerName})
}

// TODO: remove kind argument
func managedByMirroringController(CRD GenericCRD, kind string) bool {
	if CRD.GetAnnotations()[managedBy] != controllerName {
		klog.Errorf("failed to update mirroring %s %s/%s as it is not managed by %s anymore", kind, CRD.GetNamespace(), CRD.GetName(), controllerName)
		return false
	}
	return true
}

func getLegacyCRDFromDeleteAction(obj interface{}) interface{} {
	switch obj.(type) {
	case *legacysecurity.NetworkPolicy,
		*legacysecurity.ClusterNetworkPolicy,
		*legacyops.Traceflow,
		*legacycore.ExternalEntity,
		*legacycore.ClusterGroup:
		return obj
	}

	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
		return nil
	}

	switch tombstone.Obj.(type) {
	case *legacysecurity.NetworkPolicy,
		*legacysecurity.ClusterNetworkPolicy,
		*legacyops.Traceflow,
		*legacycore.ExternalEntity,
		*legacycore.ClusterGroup:
		return tombstone.Obj
	}
	utilruntime.HandleError(fmt.Errorf("Tombstone contained object that is not an legacyclient legacyCNP resource: %#v", obj))
	return nil
}

func getCRDFromDeleteAction(obj interface{}) interface{} {
	switch obj.(type) {
	case *security.NetworkPolicy,
		*security.ClusterNetworkPolicy,
		*ops.Traceflow,
		*core.ExternalEntity,
		*core.ClusterGroup:
		return obj
	}

	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
		return nil
	}

	switch tombstone.Obj.(type) {
	case *security.NetworkPolicy,
		*security.ClusterNetworkPolicy,
		*ops.Traceflow,
		*core.ExternalEntity,
		*core.ClusterGroup:
		return tombstone.Obj
	}
	utilruntime.HandleError(fmt.Errorf("Tombstone contained object that is not an legacyclient legacyCNP resource: %#v", obj))
	return nil
}
