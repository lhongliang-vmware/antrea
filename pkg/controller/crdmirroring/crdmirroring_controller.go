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
	"strings"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
)

type ACTION string
type TARGET string

const (
	// maxRetries is the number of times an legacy CRD resource will be retried
	// before it is dropped out of the queue.
	maxRetries     = 15
	defaultWorkers = 4

	managedBy      = "managed-by"
	controllerName = "crdmirroring-controller"

	mirroringStatus = "mirrored"
	mirrored        = "mirrored"

	ADD    ACTION = "add"
	UPDATE ACTION = "update"
	DELETE ACTION = "delete"
	CHECK  ACTION = "check"
	NONE   ACTION = "none"

	new    TARGET = "new"
	legacy TARGET = "legacy"
	empty  TARGET = "empty"

	NetworkPolicy        = "NetworkPolicy"
	ClusterNetworkPolicy = "ClusterNetworkPolicy"
	Tier                 = "Tier"
	ClusterGroup         = "ClusterGroup"
	ExternalEntity       = "ExternalEntity"
	Traceflow            = "Traceflow"
)

type Controller struct {
	informer           GenericInformer
	listerSycned       cache.InformerSynced
	legacyInformer     GenericInformer
	legacyListerSynced cache.InformerSynced

	CRDClient       crdclientset.Interface
	legacyCRDClient legacycrdclientset.Interface

	CRDName          string
	workerLoopPeriod time.Duration
	queue            workqueue.RateLimitingInterface

	MirroringHandler MirroringHandler
}

func NewController(genericInformer, legacyGenericInformer GenericInformer,
	CRDClient crdclientset.Interface,
	legacyCRDClient legacycrdclientset.Interface,
	CRDName string,
) *Controller {
	c := &Controller{
		informer:         genericInformer,
		legacyInformer:   legacyGenericInformer,
		CRDClient:        CRDClient,
		legacyCRDClient:  legacyCRDClient,
		CRDName:          CRDName,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), fmt.Sprintf("%v_mirroring", CRDName)),
		workerLoopPeriod: time.Second,
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNewCRDAdd,
		UpdateFunc: c.onNewCRDUpdate,
		DeleteFunc: c.onNewCRDDelete,
	}
	legacyHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onLegacyCRDAdd,
		UpdateFunc: c.onLegacyCRDUpdate,
		DeleteFunc: c.onLegacyCRDDelete,
	}

	c.informer.Informer().AddEventHandler(handlers)
	c.listerSycned = c.informer.Informer().HasSynced
	c.legacyInformer.Informer().AddEventHandler(legacyHandlers)
	c.legacyListerSynced = c.legacyInformer.Informer().HasSynced

	switch c.CRDName {
	case NetworkPolicy:
		c.MirroringHandler = NewNetworkPolicyHandler(c)
	case ClusterNetworkPolicy:
		c.MirroringHandler = NewClusterNetworkPolicyHandler(c)
	case Tier:
		c.MirroringHandler = NewTierHandler(c)
	case ClusterGroup:
		c.MirroringHandler = NewClusterGroupHandler(c)
	case ExternalEntity:
		c.MirroringHandler = NewExternalEntityHandler(c)
	case Traceflow:
		c.MirroringHandler = NewTraceflowHandler(c)
	}

	return c
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting %vMirroringController", c.CRDName)
	defer klog.Infof("Shutting down %vMirroringController", c.CRDName)

	if !cache.WaitForNamedCacheSync(fmt.Sprintf("%vMirroringController", c.CRDName), stopCh, c.listerSycned, c.legacyListerSynced) {
		return
	}

	klog.Infof("Starting %d worker threads", defaultWorkers)
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(cKey)

	err := c.syncCRD(cKey.(string))
	c.handleErr(err, cKey)

	return true
}

func (c *Controller) syncCRD(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing for %q legacy CRD. (%v)", key, time.Since(startTime))
	}()

	klog.V(4).Infof("Sync legacy CRD (%q)", key)
	action, target, nn, err := getMirroringInfo(key)
	if err != nil {
		c.queue.Forget(key)
		return nil
	}
	namespace, name, err := cache.SplitMetaNamespaceKey(nn)
	if err != nil {
		c.queue.Forget(key)
		return nil
	}

	switch action {
	case ADD:
		err = c.MirroringHandler.MirroringADD(namespace, name)
	case UPDATE:
		err = c.MirroringHandler.MirroringUPDATE(target, namespace, name)
	case DELETE:
		err = c.MirroringHandler.MirroringDELETE(target, namespace, name)
	case CHECK:
		err = c.MirroringHandler.MirroringCHECK(target, namespace, name)
	}
	if err != nil {
		return err
	}

	return nil
}

func getMirroringInfo(key string) (ACTION, TARGET, string, error) {
	temp := strings.Split(key, "_")
	if len(temp) < 3 {
		return NONE, empty, "", fmt.Errorf("couldn't get ACTION and TARGET for key %s", key)
	}
	return ACTION(temp[len(temp)-2]), TARGET(temp[len(temp)-1]), strings.Join(temp[:len(temp)-2], "_"), nil
}

func (c *Controller) queueMirroringInfo(obj interface{}, action ACTION, target TARGET) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v (type %T): %v", obj, obj, err))
		return
	}
	c.queue.Add(fmt.Sprintf("%s_%v_%v", key, action, target))
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		klog.Warningf("Error mirroring legacy CRD for %q resource, retrying. Error: %v", key, err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.Warningf("Retry budget exceeded, dropping %q legacy CRD resource out of the queue: %v", key, err)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}
