// Copyright (c) 2020 Doc.ai and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"testing"
	"time"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.ligato.io/vpp-agent/v3/proto/ligato/configurator"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp"
	vppInt "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"github.com/networkservicemesh/sdk-vppagent/pkg/networkservice/metrics"
	"github.com/networkservicemesh/sdk-vppagent/pkg/networkservice/vppagent"
	"github.com/networkservicemesh/sdk-vppagent/test/dockertest"
)

func TestMonitorChain(t *testing.T) {
	dt := dockertest.NewDockerTest(t)
	defer dt.Stop()
	dt.Setup()

	client := dt.GetGRPCClientConn()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Prepare kernel connection between alpine1 to alpine2

	metricServer := metrics.NewServer(1*time.Second, configurator.NewStatsPollerServiceClient(client))

	conn := newConnection()

	// Let's use a bit of fake chain to create a connection between

	dt.ApplyKernelConnection(dt.GetClients()[0], dt.GetClients()[1])

	ctx = vppagent.WithConfig(ctx)
	updateVPPConfig(ctx)

	// We need to setup interface between agent1 and agent2

	// After this call we will start monitoring of events, so we need to do some call
	_, err := metricServer.Request(ctx, &networkservice.NetworkServiceRequest{
		// Request "mgmt" as interface
		Connection: conn,
	})
	require.Nil(t, err)

	var metricValue map[string]string

	execResponse := ""
	execResponse, err = dt.GetClients()[0].Exec("ip", "addr")
	require.Nil(t, err)
	logrus.Infof("Client1 ip addr %v", execResponse)
	for {
		execResponse, err = dt.GetClients()[0].Exec("ping", "10.30.1.2", "-w", "5")
		require.Nil(t, err)
		logrus.Infof("Ping result: %v", execResponse)
		require.Nil(t, ctx.Err())
		// Check if we have some metrics inside
		resp, _ := metricServer.Request(ctx, &networkservice.NetworkServiceRequest{
			// Request "mgmt" as interface
			Connection: conn,
		})
		require.NotNil(t, resp)
		metricValue = resp.GetPath().GetPathSegments()[0].GetMetrics()
		// Check if resp has has metrics, and if so we checked all is ok
		if hasNonZero(metricValue) {
			break
		}
	}
	require.True(t, len(metricValue) > 0)
}

func updateVPPConfig(ctx context.Context) {
	conf := vppagent.Config(ctx)

	if conf.VppConfig == nil {
		conf.VppConfig = &vpp.ConfigData{}
	}
	// Put one interface we are interested for.
	conf.VppConfig.Interfaces = append(conf.VppConfig.Interfaces, &vppInt.Interface{
		Name: "SRC-1-id0", // Use our management interface
	})
}

func newConnection() *networkservice.Connection {
	conn := &networkservice.Connection{
		Id: "id",
		Path: &networkservice.Path{
			PathSegments: []*networkservice.PathSegment{
				{
					Id:   "local",
					Name: "local",
				},
			},
		},
	}
	return conn
}

func hasNonZero(m map[string]string) bool {
	// Check if some of values != 0
	for _, v := range m {
		if v != "0" {
			return true
		}
	}
	return false
}
