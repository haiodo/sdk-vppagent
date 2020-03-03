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

// Package metrics - implement vpp based metrics collector service, it update connection on passing Request() with set of new metrics received during interval
package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.ligato.io/vpp-agent/v3/proto/ligato/configurator"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/tools/serialize"
	"github.com/sirupsen/logrus"

	"github.com/networkservicemesh/sdk-vppagent/pkg/networkservice/vppagent"
)

type metricsServer struct {
	interval        time.Duration
	connections     map[string]*connectionInfo
	vppConnections  map[string]string
	executor        serialize.Executor
	vppClient       configurator.StatsPollerServiceClient
	collectorCancel context.CancelFunc
}

type connectionInfo struct {
	connectionID string
	index        uint32
	metrics      map[string]string
	ifName       string
}

func (s *metricsServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	conf := vppagent.Config(ctx)
	if conf == nil {
		return nil, errors.New("VPPAgent config is missing")
	}
	ifaces := conf.GetVppConfig().GetInterfaces()
	if len(ifaces) == 0 {
		return nil, errors.New("VPPAgent config should contain at least one interface")
	}

	index := request.GetConnection().GetPath().GetIndex()

	conn, err := next.Server(ctx).Request(ctx, request)
	if err == nil {
		<-s.executor.AsyncExec(func() {
			if len(s.connections) == 0 {
				// Start collector go routine.
				ctx, cancel := context.WithCancel(context.Background())
				s.collectorCancel = cancel
				go s.collect(ctx)
			}
			info := s.connections[conn.GetId()]
			if info == nil {
				info = &connectionInfo{
					connectionID: conn.GetId(),
					index:        conn.GetPath().GetIndex(),
					metrics:      map[string]string{},
					ifName:       ifaces[0].Name,
				}
				s.connections[conn.GetId()] = info
				// Store interface name to store values into
				s.vppConnections[info.ifName] = info.connectionID
			}
			// Update connection with metrics
			if len(info.metrics) > 0 && len(conn.GetPath().GetPathSegments()) > int(index) {
				conn.GetPath().GetPathSegments()[index].Metrics = info.metrics
			}
		})
	}
	return conn, err
}

func (s *metricsServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	s.executor.AsyncExec(func() {
		info := s.connections[conn.GetId()]
		if info != nil {
			delete(s.connections, info.connectionID)
			delete(s.vppConnections, info.ifName)
		}
		if len(s.connections) == 0 && s.collectorCancel != nil {
			s.collectorCancel()
			s.collectorCancel = nil
		}
	})
	return next.Server(ctx).Close(ctx, conn)
}

// NewServer creates a new metrics collector instance
func NewServer(interval time.Duration, vppClient configurator.StatsPollerServiceClient) networkservice.NetworkServiceServer {
	rv := &metricsServer{
		connections:    map[string]*connectionInfo{},
		vppConnections: map[string]string{},
		interval:       interval,
		vppClient:      vppClient,
	}
	return rv
}

func (s *metricsServer) collect(ctx context.Context) {
	logrus.Errorf("MetricsCollector: Start collector")
	req := &configurator.PollStatsRequest{
		PeriodSec: uint32(s.interval.Seconds()),
	}
	stream, err := s.vppClient.PollStats(ctx, req)
	if err != nil {
		logrus.Errorf("MetricsCollector: PollStats err: %v", err)
		return
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			logrus.Errorf("MetricsCollector: stream.Recv() err: %v", err)
		} else {
			vppStats := resp.GetStats().GetVppStats()
			if vppStats.Interface != nil {
				s.updateStatistics(vppStats.Interface)
			}
			logrus.Infof("MetricsCollector: GetStats(): %v", vppStats)
		}
		select {
		case <-ctx.Done():
			logrus.Errorf("MetricsCollector: Monitor poll canceled")
			return
		case <-time.After(s.interval):
		}
	}
}
func (s *metricsServer) updateStatistics(stats *vpp_interfaces.InterfaceStats) {
	metrics := make(map[string]string)
	metrics["rx_bytes"] = fmt.Sprint(stats.Rx.Bytes)
	metrics["tx_bytes"] = fmt.Sprint(stats.Tx.Bytes)
	metrics["rx_packets"] = fmt.Sprint(stats.Rx.Packets)
	metrics["tx_packets"] = fmt.Sprint(stats.Tx.Packets)
	metrics["rx_error_packets"] = fmt.Sprint(stats.RxError)
	metrics["tx_error_packets"] = fmt.Sprint(stats.TxError)
	s.executor.AsyncExec(func() {
		if connID, ok := s.vppConnections[stats.Name]; ok {
			info := s.connections[connID]
			info.metrics = metrics
		}
	})
}
