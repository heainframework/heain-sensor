module github.com/heainframework/heain-sensor

go 1.24.7

require (
	github.com/heainframework/heain-sdk v0.0.0-00010101000000-000000000000
	go.etcd.io/bbolt v1.4.1
)

require (
	golang.org/x/sys v0.29.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/heainframework/heain-sdk => ../heain-sdk
