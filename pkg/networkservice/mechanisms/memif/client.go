// Copyright (c) 2020 Cisco Systems, Inc.
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

// Package memif provides networkservice chain elements that support the memif Mechanism
package memif

import (
	"context"
	"fmt"
	"path"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/ligato/vpp-agent/api/models/vpp"
	vppinterfaces "github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/connection"
	"github.com/networkservicemesh/api/pkg/api/connection/mechanisms/cls"
	"github.com/networkservicemesh/api/pkg/api/connection/mechanisms/memif"
	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk-vppagent/pkg/networkservice/vppagent"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type memifClient struct {
	baseDir string
}

// NewClient provides a NetworkServiceClient chain elements that support the memif Mechanism
func NewClient(baseDir string) networkservice.NetworkServiceClient {
	return &memifClient{baseDir: baseDir}
}

func (m *memifClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*connection.Connection, error) {
	mechanism := &connection.Mechanism{
		Cls:        cls.LOCAL,
		Type:       memif.MECHANISM,
		Parameters: make(map[string]string),
	}
	request.MechanismPreferences = append(request.MechanismPreferences, mechanism)
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}
	m.appendInterfaceConfig(ctx, conn)
	return conn, nil
}

func (m *memifClient) Close(ctx context.Context, conn *connection.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	m.appendInterfaceConfig(ctx, conn)
	return next.Client(ctx).Close(ctx, conn, opts...)
}

func (m *memifClient) appendInterfaceConfig(ctx context.Context, conn *connection.Connection) {
	if mechanism := memif.ToMechanism(conn.GetMechanism()); mechanism != nil {
		conf := vppagent.Config(ctx)
		conf.GetVppConfig().Interfaces = append(conf.GetVppConfig().Interfaces, &vpp.Interface{
			Name:    fmt.Sprintf("client-%s", conn.GetId()),
			Type:    vppinterfaces.Interface_MEMIF,
			Enabled: true,
			Link: &vppinterfaces.Interface_Memif{
				Memif: &vppinterfaces.MemifLink{
					Master:         false,
					SocketFilename: path.Join(m.baseDir, mechanism.GetSocketFilename()),
				},
			},
		})
	}
}
