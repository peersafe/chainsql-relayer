#! /bin/bash

# disable 
# warning: 'TARGET_OS_MAC' is not defined, evaluates to 0 [-Wundef-prefix=TARGET_OS_]
go env -w CGO_ENABLED=0
go build -o ./bin/chainsql-relayer main.go
go env -w CGO_ENABLED=1
