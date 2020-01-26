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

// Package kernelvethpair provides networkservice chain elements that support the kernel Mechanism using veth pairs
package kernelvethpair

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/api/pkg/api/connection"
	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type kernelVethPairServer struct{}

// NewServer provides NetworkServiceServer chain elements that support the kernel Mechanism using veth pairs
func NewServer() networkservice.NetworkServiceServer {
	return &kernelVethPairServer{}
}

func (k *kernelVethPairServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*connection.Connection, error) {
	conn, err := next.Server(ctx).Request(ctx, request)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err := appendInterfaceConfig(ctx, conn, fmt.Sprintf("server-%s", conn.GetId())); err != nil {
		return nil, err
	}
	return conn, nil
}

func (k *kernelVethPairServer) Close(ctx context.Context, conn *connection.Connection) (*empty.Empty, error) {
	if err := appendInterfaceConfig(ctx, conn, fmt.Sprintf("server-%s", conn.GetId())); err != nil {
		return nil, err
	}
	return next.Server(ctx).Close(ctx, conn)
}
