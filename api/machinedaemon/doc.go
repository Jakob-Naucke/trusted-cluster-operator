// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// Package machinedaemon has no Go types. It exists only to hold the
// kubebuilder RBAC markers for the TEC machine daemon's ServiceAccount,
// which controller-gen renders into its own ClusterRole, separate from the
// operator's. The daemon itself is implemented in Rust.
//
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=machines,verbs=get;list;watch
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=machines/status,verbs=get;patch;update
// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=trustee-certs,verbs=get;watch
package machinedaemon
