module sg9

go 1.24.7

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.39.0
	golang.org/x/exp => github.com/golang/exp v0.0.0-20250506013437-ce4c2cf36ca6
	golang.org/x/mod => github.com/golang/mod v0.25.0
	golang.org/x/net => github.com/golang/net v0.41.0
	golang.org/x/sync => github.com/golang/sync v0.15.0
	golang.org/x/sys => github.com/golang/sys v0.33.0
	golang.org/x/telemetry => github.com/golang/telemetry v0.0.0-20240521205824-bda55230c457
	golang.org/x/term => github.com/golang/term v0.32.0
	golang.org/x/text => github.com/golang/text v0.26.0
	golang.org/x/time => github.com/golang/time v0.11.0
	golang.org/x/tools => github.com/golang/tools v0.33.0
	golang.org/x/xerrors => github.com/golang/xerrors v0.0.0-20240903120638-7835f813f4da
	gopkg.in/yaml.v3 => ./third_party/yamlstub
)

require (
	github.com/pkg/sftp v1.13.9
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
)

require (
	github.com/kr/fs v0.1.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
)
