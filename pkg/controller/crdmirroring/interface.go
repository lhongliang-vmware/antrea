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

import "k8s.io/client-go/tools/cache"

type GenericInformer interface {
	Informer() cache.SharedIndexInformer
}

type GenericCRD interface {
	GetAnnotations() map[string]string
	GetNamespace() string
	GetName() string
	GetLabels() map[string]string
	SetAnnotations(map[string]string)
	SetNamespace(string)
	SetName(string)
	SetLabels(map[string]string)
}

type MirroringHandler interface {
	MirroringADD(namespace, name string) error
	MirroringUPDATE(target TARGET, namespace, name string) error
	MirroringDELETE(target TARGET, namespace, name string) error
	MirroringCHECK(target TARGET, namespace, name string) error
}
