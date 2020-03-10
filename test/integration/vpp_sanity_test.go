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

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.ligato.io/vpp-agent/v3/proto/ligato/configurator"

	"github.com/networkservicemesh/sdk-vppagent/test/dockertest"
)

func TestVppAgentStart(t *testing.T) {
	dt := dockertest.NewDockerTest(t)
	defer dt.Stop()
	dt.Setup()

	for _, c := range dt.GetContainers() {
		require.Equal(t, true, c.GetStatus().State.Running)
		logrus.Infof("Logs: %s", c.GetLogs())
	}

	client := dt.GetClient()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	response, err := client.Get(ctx2, &configurator.GetRequest{})
	require.NotNil(t, response)
	require.Nil(t, err)

	// Check we have management interface
	require.Equal(t, 1, len(response.Config.VppConfig.Interfaces))
	require.Equal(t, "mgmt", response.Config.VppConfig.Interfaces[0].Name)

	dt.Stop()

	for _, c := range dt.GetContainers() {
		require.Equal(t, false, c.GetStatus().State.Running)
	}
}
