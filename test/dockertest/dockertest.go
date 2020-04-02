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

// Package dockertest - is a helper tool packages to test vppagent using docker with few instances of vppagent
package dockertest

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	linux_namespace "go.ligato.io/vpp-agent/v3/proto/ligato/linux/namespace"
	"golang.org/x/text/runes"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.ligato.io/vpp-agent/v3/proto/ligato/configurator"
	"go.ligato.io/vpp-agent/v3/proto/ligato/linux"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	"go.ligato.io/vpp-agent/v3/proto/ligato/vpp"
	vpp_acl "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/acl"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"
	vpp_l3 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"google.golang.org/grpc"
)

const (
	dockerTimeout  = 120 * time.Second
	ligatoVppAgent = "ligato/vpp-agent:v3.1.0"
)

// DockerTest - a base interface for docker setup of vpp agent configuration
type DockerTest interface {
	// Pull required image from docker hub
	PullImage(name string)
	// Setup - prepare vppagent environment and few docker alpine images.
	Setup()
	Stop()
	GetContainers() []DockerContainer
	GetClients() []DockerContainer
	GetClient() configurator.ConfiguratorServiceClient
	ConfigurationClientConn() grpc.ClientConnInterface

	ApplyKernelConnection(client1, client2 DockerContainer)
}

// DockerContainer - represent a container running inside docker
type DockerContainer interface {
	// Start - start a container
	Start()
	// Stop - stop a container
	Stop()
	// GetStatus - retrieve a container status
	GetStatus() types.ContainerJSON
	// GetLogs- Get current container logs
	GetLogs() string
	// CopyToContainer -  Copy some file to container
	CopyToContainer(targetDir, targetFile, content string)

	// LogWaitPattern-  Wait for logs pattern
	LogWaitPattern(pattern string, timeout time.Duration)

	// Exec - execute command inside container
	Exec(command ...string) (string, error)
	// GetNetNS - retrieve a linux namesoaice inode container
	GetNetNS() string
	// GetID - return docker id for container
	GetID() string
}

type dockerTest struct {
	connection *client.Client
	t          require.TestingT
	containers []DockerContainer
	vppConn    *grpc.ClientConn
	client     configurator.ConfiguratorServiceClient

	vppAgent DockerContainer
}

// GetInode returns Inode for file
func GetInode(file string) (uint64, error) {
	fileinfo, err := os.Stat(file)
	if err != nil {
		return 0, errors.Wrap(err, "error stat file")
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a stat_t")
	}
	return stat.Ino, nil
}
func (d *dockerTest) ApplyKernelConnection(client1, client2 DockerContainer) {
	ns1 := client1.GetNetNS()
	logrus.Infof("Agent1 netNS: %v", ns1)
	ns2 := client2.GetNetNS()
	logrus.Infof("Agent2 netNS: %v", ns2)

	s1 := client1.GetStatus()
	s2 := client2.GetStatus()

	ip1 := "10.30.1.1/30"
	ip2 := "10.30.1.2/30"

	logrus.Infof("Agent1 ip %v mac %v", ip1, s1.NetworkSettings.MacAddress)
	logrus.Infof("Agent2 ip %v mac %v", ip2, s2.NetworkSettings.MacAddress)

	net1File, err := d.vppAgent.Exec("python", "/bin/find-net-ns.py", ns1)
	require.Nil(d.t, err)
	net2File, err2 := d.vppAgent.Exec("python", "/bin/find-net-ns.py", ns2)
	require.Nil(d.t, err2)

	logrus.Infof("Agent1 ip %v net %v", ip1, net1File)
	logrus.Infof("Agent2 ip %v net %v", ip2, net2File)

	rv := &configurator.Config{
		LinuxConfig: &linux.ConfigData{},
		VppConfig:   &vpp.ConfigData{},
	}

	// Source configuration
	d.addKernelConnection(rv, "SRC-1-id0", ip1, s1, net1File)
	d.addKernelConnection(rv, "DST-1-id1", ip2, s2, net2File)

	if len(rv.VppConfig.Interfaces) == 2 {
		ifaces := rv.VppConfig.Interfaces[len(rv.VppConfig.Interfaces)-2:]
		rv.VppConfig.XconnectPairs = append(rv.VppConfig.XconnectPairs, []*vpp_l2.XConnectPair{
			{
				ReceiveInterface:  ifaces[0].Name,
				TransmitInterface: ifaces[1].Name,
			},
			{
				ReceiveInterface:  ifaces[1].Name,
				TransmitInterface: ifaces[0].Name,
			},
		}...)
	}
	dataRequest := &configurator.UpdateRequest{
		Update: rv,
	}
	logrus.Infof("Setting up Mgmt Interface %v", dataRequest)
	resp, err := d.client.Update(context.Background(), dataRequest)
	require.Nil(d.t, err)
	require.NotNil(d.t, resp)
}

func (d *dockerTest) addKernelConnection(rv *configurator.Config, name, ip string, containerJSON types.ContainerJSON, netNSFile string) {
	rv.LinuxConfig.Interfaces = append(rv.LinuxConfig.Interfaces, []*linux_interfaces.Interface{
		{
			Name:       name + "-veth",
			Type:       linux_interfaces.Interface_VETH,
			Enabled:    true,
			HostIfName: name + "-veth",
			Link: &linux_interfaces.Interface_Veth{
				Veth: &linux_interfaces.VethLink{
					PeerIfName:           name,
					RxChecksumOffloading: linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED,
					TxChecksumOffloading: linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED,
				},
			},
		},
		{
			Name:        name,
			Type:        linux_interfaces.Interface_VETH,
			Enabled:     true,
			IpAddresses: []string{ip},
			PhysAddress: containerJSON.NetworkSettings.MacAddress,
			HostIfName:  "nsm-" + name,
			Namespace: &linux_namespace.NetNamespace{
				Type:      linux_namespace.NetNamespace_FD,
				Reference: netNSFile,
			},
			Link: &linux_interfaces.Interface_Veth{
				Veth: &linux_interfaces.VethLink{
					PeerIfName:           name + "-veth",
					RxChecksumOffloading: linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED,
					TxChecksumOffloading: linux_interfaces.VethLink_CHKSM_OFFLOAD_DISABLED,
				},
			},
		},
	}...)
	rv.VppConfig.Interfaces = append(rv.VppConfig.Interfaces, &vpp_interfaces.Interface{
		Name:    name,
		Type:    vpp_interfaces.Interface_AF_PACKET,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Afpacket{
			Afpacket: &vpp_interfaces.AfpacketLink{
				LinuxInterface: name + "-veth",
			},
		},
	})
}

func (d *dockerTest) GetContainers() []DockerContainer {
	return d.containers
}
func (d *dockerTest) GetClients() []DockerContainer {
	result := []DockerContainer{}
	for _, c := range d.containers {
		if c.GetID() != d.vppAgent.GetID() {
			result = append(result, c)
		}
	}
	return result
}
func (d *dockerTest) ConfigurationClientConn() grpc.ClientConnInterface {
	return d.vppConn
}

type dockerContainer struct {
	d           *dockerTest
	containerID string
	name        string
}

type nonASCIISet struct {
}

func (nonASCIISet) Contains(r rune) bool {
	return r < 32 || r >= 127
}

func removeControlCharacters(str string) string {
	str, _, _ = transform.String(transform.Chain(norm.NFKD, runes.Remove(nonASCIISet{})), str)
	return str
}

func (d *dockerContainer) GetID() string {
	return d.containerID
}

func (d *dockerContainer) Exec(command ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	respID, err := d.d.connection.ContainerExecCreate(ctx, d.containerID, types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          command,
	})
	require.Nil(d.d.t, err)

	resp, err2 := d.d.connection.ContainerExecAttach(ctx, respID.ID, types.ExecConfig{
		AttachStderr: true,
		AttachStdout: true,
		Tty:          true,
	})
	require.Nil(d.d.t, err2)
	response := ""

	for {
		select {
		case <-ctx.Done():
		default:
			line, readErr := resp.Reader.ReadString('\n')
			response += removeControlCharacters(line) + "\n"
			if readErr != nil {
				// End of read
				return strings.TrimSpace(response), nil
			}
		}
	}
}

func (d *dockerContainer) GetNetNS() string {
	link, err := d.Exec("readlink", "/proc/self/ns/net")
	require.Nil(d.d.t, err)

	pattern := regexp.MustCompile(`net:\[(.*)\]`)
	matches := pattern.FindStringSubmatch(link)
	require.True(d.d.t, len(matches) >= 1)

	return matches[1]
}

func (d *dockerContainer) LogWaitPattern(pattern string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	r, err := regexp.Compile(pattern)
	if err != nil {
		require.Failf(d.d.t, "failed to compile pattern: %v %v", pattern, err)
	}
	matcher := func(s string) bool {
		return r.FindStringSubmatch(s) != nil
	}

	for {
		curLogs := d.GetLogs()
		lines := strings.Split(curLogs, "\n")
		nl := ""
		for i, line := range lines {
			// trim non ansi
			line = removeControlCharacters(line)
			if i == len(lines)-1 {
				logrus.Infof("q")
			}
			if len(line) > 0 {
				nl = line
			}
			if matcher(nl) {
				return
			}
		}
		// Find pattern
		select {
		case <-ctx.Done():
			require.Failf(d.d.t, "Timeout waiting for pattern %v %v\n Logs:", d.containerID, pattern, curLogs)
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func generate(name, content string) (io.Reader, error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	hdr := &tar.Header{
		Name: name,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

func (d *dockerContainer) CopyToContainer(targetDir, targetFile, content string) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	tarFile, err := generate(targetFile, content)
	require.Nil(d.d.t, err)

	err = d.d.connection.CopyToContainer(ctx, d.containerID, targetDir, tarFile, types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
	})
	require.Nil(d.d.t, err)
}

func (d *dockerContainer) GetStatus() types.ContainerJSON {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	info, err := d.d.connection.ContainerInspect(ctx, d.containerID)
	require.Nil(d.d.t, err)
	return info
}

func (d *dockerContainer) Stop() {
	d.d.stopContainer(d.name, d.containerID)
}

func (d *dockerTest) stopContainer(name, containerID string) {
	logrus.Infof("Stopping container: %v", name)
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	timeout := 0 * time.Millisecond

	info, err := d.connection.ContainerInspect(ctx, containerID)
	if err != nil {
		logrus.Errorf("Failed to get container information %v", err)
	}
	if info.State != nil && info.State.Running {
		err = d.connection.ContainerStop(ctx, containerID, &timeout)
		if err != nil {
			logrus.Errorf("failed to stop container %v", err)
		}
	}
	logrus.Infof("container stopped %v %v", name, containerID)
}

func (d *dockerContainer) Start() {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	err := d.d.connection.ContainerStart(ctx, d.containerID, types.ContainerStartOptions{})
	require.Nil(d.d.t, err)

	info := types.ContainerJSON{}
	for {
		select {
		case <-ctx.Done():
			require.Failf(d.d.t, "Failed to wait for container running state %v %v", d.name, d.containerID)
			return
		case <-time.After(10 * time.Millisecond):
		}
		info = d.GetStatus()
		curLogs := d.GetLogs()
		logrus.Infof("Staring logs:" + curLogs)
		if info.State != nil && info.State.Running {
			// Container is running all is ok
			break
		}
	}
	require.NotNil(d.d.t, info.State)
	require.Equal(d.d.t, true, info.State.Running)

	logrus.Infof("Status of container creation: %v", d.GetLogs())
}

func (d *dockerContainer) GetLogs() string {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	reader, err := d.d.connection.ContainerLogs(ctx, d.containerID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Details:    true,
	})
	require.Nil(d.d.t, err)

	s := ""
	out := bytes.NewBufferString(s)
	_, _ = io.Copy(out, reader)
	_ = reader.Close()
	s = out.String()
	ss := strings.Split(s, "\n")
	s = ""
	for _, sss := range ss {
		s += strings.TrimSpace(sss) + "\n"
	}
	return s
}

func (d *dockerTest) Stop() {
	if d.vppConn != nil {
		_ = d.vppConn.Close()
		d.vppConn = nil
	}

	// Close all created containers
	for _, cnt := range d.containers {
		cnt.Stop()
	}
	err := d.connection.Close()
	require.Nil(d.t, err)
}

func conf(name string, options ...string) string {
	result := name + " {\n"
	for _, opt := range options {
		result += fmt.Sprintf("\t%s\n", opt)
	}
	result += "}\n"
	return result
}

func genVppConfig() string {
	return conf("unix",
		"nodaemon", "log /var/log/vpp/vpp.log", "full-coredump",
		"cli-listen /run/vpp/cli.sock",
		"gid vpp", "poll-sleep-usec 1000") +
		conf("api-trace", "on") +
		conf("api-segment", "gid vpp") +
		conf("socksvr", "default") +
		conf("cpu") +
		conf("plugins", "plugin dpdk_plugin.so { disable }")
}

func getGOVPPConfig() string {
	return "trace-enabled: false\n" +
		"binapi-socket-path: /run/vpp-api.sock\n" +
		"connect-via-shm: false\n" +
		"stats-socket-path: /run/vpp/stats.sock\n" +
		"resync-after-reconnect: false\n" +
		"retry-request-count: 0\n" +
		"retry-request-timeout: 500000000\n" +
		"retry-connect-count: 30\n" +
		"retry-connect-timeout: 1000000000\n"
}

func getSupervisorConfig() string {
	return "programs:\n" +
		"  - name: \"vpp\"\n" +
		"    executable-path: \"/usr/bin/vpp\"\n" +
		"    executable-args: [\"-c\", \"/etc/vpp/vpp.conf\"]\n" +
		"  - name: \"agent\"\n" +
		"    executable-path: \"/bin/vpp-agent\"\n" +
		"    executable-args: [\"--config-dir=/opt/vpp-agent/dev\"]"
}

func getRunSHScript() string {
	return "echo Starting VPP agent\n" +
		"rm /opt/vpp-agent/dev/etcd.conf\n" +
		"mkdir -p /run/vpp\n" +
		"mkdir -p /tmp/vpp/\n" +
		"mkdir -p /etc/govpp\n" +
		"cp /etc/govpp.conf /etc/govpp/govpp.conf\n" +
		"mkdir -p /var/log/vpp/\n" +
		"echo 'Endpoint: \"0.0.0.0:9111\"' > /opt/vpp-agent/dev/grpc.conf\n" +
		"rm -f /dev/shm/db /dev/shm/global_vm /dev/shm/vpe-api\n" +
		"echo running vpp-agent-init\n" +
		"vpp-agent-init\n"
}

func getTelemetryConf() string {
	return "polling-interval: 5000000000\n" +
		"disabled: false"
}

func (d *dockerTest) configureMgmtInterface(c DockerContainer) {
	cStatus := c.GetStatus()

	ipAddr := net.ParseIP(cStatus.NetworkSettings.Gateway)
	netIP := net.IPNet{
		IP:   ipAddr,
		Mask: net.CIDRMask(cStatus.NetworkSettings.IPPrefixLen, 32),
	}
	logrus.Infof("NETIP: %v", netIP.String())

	dataRequest := &configurator.UpdateRequest{
		Update: &configurator.Config{
			VppConfig: &vpp.ConfigData{
				Interfaces: d.createMgmgInterfaces(cStatus),
				// Add default route via default gateway
				Routes: d.createMgmtRoutes(cStatus),
				// Add system arp entries
				Arps: []*vpp.ARPEntry{},
			},
		},
	}
	dataRequest.Update.VppConfig.Acls = d.creareVPPACLs(dataRequest, netIP)

	logrus.Infof("Setting up Mgmt Interface %v", dataRequest)
	_, err := d.client.Update(context.Background(), dataRequest)
	require.Nil(d.t, err)
}

func (d *dockerTest) createMgmtRoutes(cStatus types.ContainerJSON) []*vpp.Route {
	return []*vpp.Route{
		{
			Type:              vpp_l3.Route_INTER_VRF,
			OutgoingInterface: "mgmt",
			DstNetwork:        "0.0.0.0/0",
			Weight:            1,
			NextHopAddr:       cStatus.NetworkSettings.Gateway,
		},
	}
}

func (d *dockerTest) createMgmgInterfaces(cStatus types.ContainerJSON) []*vpp.Interface {
	return []*vpp.Interface{
		{
			Name:    "mgmt",
			Type:    vpp_interfaces.Interface_AF_PACKET,
			Enabled: true,
			IpAddresses: []string{
				cStatus.NetworkSettings.IPAddress,
			},
			PhysAddress: cStatus.NetworkSettings.MacAddress,
			Link: &vpp_interfaces.Interface_Afpacket{
				Afpacket: &vpp_interfaces.AfpacketLink{
					HostIfName: "eth0", // TODO: Find a proper host or linux
					//LinuxInterface: interface
				},
			},
		},
	}
}

func (d *dockerTest) creareVPPACLs(dataRequest *configurator.UpdateRequest, netIP net.IPNet) []*vpp.ACL {
	return []*vpp.ACL{
		{
			Name: "NSMmgmtInterfaceACL",
			Interfaces: &vpp_acl.ACL_Interfaces{
				Ingress: []string{dataRequest.Update.VppConfig.Interfaces[0].Name},
			},
			Rules: []*vpp_acl.ACL_Rule{
				{
					Action: vpp_acl.ACL_Rule_PERMIT,
					IpRule: &vpp_acl.ACL_Rule_IpRule{
						Ip: &vpp_acl.ACL_Rule_IpRule_Ip{
							DestinationNetwork: netIP.String(),
							SourceNetwork:      "0.0.0.0/0",
						},
						Udp: &vpp_acl.ACL_Rule_IpRule_Udp{
							DestinationPortRange: &vpp_acl.ACL_Rule_IpRule_PortRange{
								LowerPort: 4789,
								UpperPort: 4789,
							},
							SourcePortRange: &vpp_acl.ACL_Rule_IpRule_PortRange{
								LowerPort: 0,
								UpperPort: 65535,
							},
						},
					},
				},
			},
		},
	}
}

func (d *dockerTest) GetClient() configurator.ConfiguratorServiceClient {
	return d.client
}

func (d *dockerTest) Setup() {
	logrus.Infof("Fetching docker images")

	d.PullImage("docker.io/library/alpine")
	d.PullImage("docker.io/" + ligatoVppAgent)

	agent := d.CreateContainer("vpp_agent", ligatoVppAgent,
		[]string{
			"/bin/sh",
			"-c",
			"chmod +x /bin/vpp-run.sh && /bin/vpp-run.sh",
		}, ContainerConfig{
			Privileged: true,
			ExposedPorts: nat.PortSet{
				"9111/tcp": {},
			},
			PortBindings: nat.PortMap{
				"9111/tcp": []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "9111",
					},
				},
			},
		})

	agent.CopyToContainer("/etc/vpp", "vpp.conf", genVppConfig())
	agent.CopyToContainer("/opt/vpp-agent/dev/", "supervisor.conf", getSupervisorConfig())
	agent.CopyToContainer("/etc/", "govpp.conf", getGOVPPConfig())
	agent.CopyToContainer("/opt/vpp-agent/dev/", "telemetry.conf", getTelemetryConf())

	agent.CopyToContainer("/bin/", "vpp-run.sh", getRunSHScript())
	agent.CopyToContainer("/bin/", "find-net-ns.py", getFindNetNSPy())
	agent.Start()
	agent.LogWaitPattern("Agent started with .* plugins \\(took .*\\)", dockerTimeout)

	d.vppAgent = agent

	c1 := d.CreateContainer("test_alpine1", "alpine", []string{"tail", "-f", "/dev/null"}, ContainerConfig{})
	c1.Start()
	c2 := d.CreateContainer("test_alpine2", "alpine", []string{"tail", "-f", "/dev/null"}, ContainerConfig{})
	c2.Start()

	// Connect via GRPC to vpp-agent

	// Let's connect to VPP agent and check it is functional.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var err error
	d.vppConn, err = grpc.DialContext(ctx, "localhost:9111", grpc.WithInsecure(), grpc.WithBlock())
	require.Nil(d.t, err)
	require.NotNil(d.t, d.vppConn)

	d.client = configurator.NewConfiguratorServiceClient(d.vppConn)

	d.configureMgmtInterface(agent)
}

func getFindNetNSPy() string {
	return "import os\n" +
		"import sys\n" +
		"import glob\n" +
		"def findContainerNS(id):\n" +
		"    for procId in [x[6:] for x in glob.glob(\"/proc/*\") if x[6:].isdigit() and os.path.exists('/proc/'+x[6:]+'/cmdline') ]:\n" +
		"        cmdName = open('/proc/' + procId +'/cmdline').readline()        \n" +
		"        nsId = os.popen('readlink /proc/' + procId + '/ns/net').read()\n" +
		"        if nsId.find(id) >=0:\n" +
		"            if cmdName.find(\"tail\\x00-f\\x00/dev/null\\x00\") >= 0:            \n" +
		"                return '/proc/' + procId +'/ns/net'\n" +
		"\n" +
		"\n" +
		"print(findContainerNS(sys.argv[1]))"
}

func (d *dockerTest) PullImage(name string) {
	logrus.Infof("Fetching docker image: %v", name)
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	reader, err := d.connection.ImagePull(ctx, name, types.ImagePullOptions{})
	require.Nil(d.t, err)
	s := ""
	out := bytes.NewBufferString(s)
	_, _ = io.Copy(out, reader)
	_ = reader.Close()
	s = out.String()
	ss := strings.Split(s, "\n")
	s = ""
	for _, sss := range ss {
		s += strings.TrimSpace(sss) + "\n"
	}
	logrus.Infof("Docker output:\n %v", s)
}

// ContainerConfig - some configurations for container created.
type ContainerConfig struct {
	Privileged   bool
	PortBindings nat.PortMap
	ExposedPorts nat.PortSet
}

func (d *dockerTest) CreateContainer(name, containerImage string, cmdLine []string, config ContainerConfig) DockerContainer {
	logrus.Infof("Creating docker container: %v %v", name, cmdLine)
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	filterValue := filters.NewArgs()
	filterValue.Add("label", "docker_test_container="+name)
	containers, err := d.connection.ContainerList(ctx, types.ContainerListOptions{
		Filters: filterValue,
	})
	require.Nil(d.t, err)

	for i := 0; i < len(containers); i++ {
		d.stopContainer(name, containers[i].ID)
	}

	resp, err := d.connection.ContainerCreate(ctx, &container.Config{
		Image:        containerImage,
		Cmd:          cmdLine,
		ExposedPorts: config.ExposedPorts,
		Labels: map[string]string{
			"docker_test_container": name,
		},
	}, &container.HostConfig{
		Privileged:   config.Privileged,
		PidMode:      "host",
		PortBindings: config.PortBindings,
	}, nil, "")
	require.NotNil(d.t, resp)
	require.Nil(d.t, err)
	result := &dockerContainer{
		name:        name,
		d:           d,
		containerID: resp.ID,
	}

	d.containers = append(d.containers, result)

	return result
}

// NewDockerTest - creates a docker testing helper infrastructure
func NewDockerTest(t require.TestingT) DockerTest {
	cli, err := client.NewEnvClient()
	require.Nil(t, err)

	return &dockerTest{
		t:          t,
		connection: cli,
	}
}
