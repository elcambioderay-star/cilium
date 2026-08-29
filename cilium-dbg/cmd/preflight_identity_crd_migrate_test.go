// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestIsLocalClusterInfoSet(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		expected bool
	}{
		{
			name: "empty",
		},
		{
			name: "missing cluster ID",
			config: map[string]any{
				cmtypes.OptClusterName:          "cluster-1",
				cmtypes.OptMaxConnectedClusters: uint32(255),
			},
		},
		{
			name: "missing cluster name",
			config: map[string]any{
				cmtypes.OptClusterID:            uint32(1),
				cmtypes.OptMaxConnectedClusters: uint32(255),
			},
		},
		{
			name: "missing max connected clusters",
			config: map[string]any{
				cmtypes.OptClusterID:   uint32(1),
				cmtypes.OptClusterName: "cluster-1",
			},
		},
		{
			name: "complete",
			config: map[string]any{
				cmtypes.OptClusterID:            uint32(1),
				cmtypes.OptClusterName:          "cluster-1",
				cmtypes.OptMaxConnectedClusters: uint32(255),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := viper.New()
			for key, value := range tt.config {
				vp.Set(key, value)
			}

			require.Equal(t, tt.expected, isLocalClusterInfoSet(vp))
		})
	}
}

func TestClusterInfoFromConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		expected cmtypes.ClusterInfo
		wantErr  string
	}{
		{
			name: "API response values",
			config: map[string]any{
				"ClusterID":            float64(42),
				"ClusterName":          "cluster-42",
				"MaxConnectedClusters": float64(511),
			},
			expected: cmtypes.ClusterInfo{
				ID:                   42,
				Name:                 "cluster-42",
				MaxConnectedClusters: 511,
			},
		},
		{
			name: "missing cluster ID",
			config: map[string]any{
				"ClusterName":          "cluster-1",
				"MaxConnectedClusters": uint32(255),
			},
			wantErr: "missing ClusterID",
		},
		{
			name: "invalid cluster ID",
			config: map[string]any{
				"ClusterID":            "invalid",
				"ClusterName":          "cluster-1",
				"MaxConnectedClusters": uint32(255),
			},
			wantErr: "invalid ClusterID",
		},
		{
			name: "missing cluster name",
			config: map[string]any{
				"ClusterID":            uint32(1),
				"MaxConnectedClusters": uint32(255),
			},
			wantErr: "missing ClusterName",
		},
		{
			name: "invalid cluster name",
			config: map[string]any{
				"ClusterID":            uint32(1),
				"ClusterName":          1,
				"MaxConnectedClusters": uint32(255),
			},
			wantErr: "invalid ClusterName",
		},
		{
			name: "missing max connected clusters",
			config: map[string]any{
				"ClusterID":   uint32(1),
				"ClusterName": "cluster-1",
			},
			wantErr: "missing MaxConnectedClusters",
		},
		{
			name: "invalid max connected clusters",
			config: map[string]any{
				"ClusterID":            uint32(1),
				"ClusterName":          "cluster-1",
				"MaxConnectedClusters": "invalid",
			},
			wantErr: "invalid MaxConnectedClusters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := clusterInfoFromConfig(tt.config)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}
