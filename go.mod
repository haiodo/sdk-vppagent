module github.com/networkservicemesh/sdk-vppagent

go 1.13

require (
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/kr/pretty v0.2.0 // indirect
	github.com/ligato/cn-infra v2.2.0+incompatible // indirect
	github.com/ligato/vpp-agent v2.5.1+incompatible
	github.com/networkservicemesh/api v0.2.0
	github.com/networkservicemesh/sdk v0.0.0
	github.com/onsi/gomega v1.8.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	google.golang.org/grpc v1.26.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)

replace github.com/networkservicemesh/api => github.com/networkservicemesh/api v0.0.0-20200125205131-0623273c4e70

replace github.com/networkservicemesh/sdk => github.com/networkservicemesh/sdk v0.0.0-20200126180355-103bfac91336

replace github.com/satori/go.uuid => github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
