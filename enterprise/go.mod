module github.com/coder/exectrace/enterprise

go 1.19

replace github.com/coder/exectrace => ../

require (
	cdr.dev/slog v1.4.1
	github.com/coder/exectrace v0.1.0
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/stretchr/testify v1.8.1
	github.com/urfave/cli/v2 v2.23.7
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2
	k8s.io/utils v0.0.0-20230115233650-391b47cb4029
)

require (
	github.com/cilium/ebpf v0.10.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
)
