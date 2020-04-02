module github.com/networkservicemesh/sdk-vppagent/test/integration

go 1.13

require (
	github.com/networkservicemesh/api v0.0.0-20200323163158-d70a2540052a
	github.com/networkservicemesh/sdk-vppagent v0.0.0-20200226130054-b405aac645ab
	github.com/networkservicemesh/sdk-vppagent/test/dockertest v0.0.0-20200226130054-b405aac645ab
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.4.0
	go.ligato.io/vpp-agent/v3 v3.1.0
	google.golang.org/grpc v1.27.1
)

replace (
	github.com/networkservicemesh/sdk-vppagent => ../..
	github.com/networkservicemesh/sdk-vppagent/test/dockertest => ../dockertest
)
