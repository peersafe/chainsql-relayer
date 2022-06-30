#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

RCWalletPwd="peersafe"
RCRPCAddress="http://127.0.0.1:20336"
RegisterSideChain=0
SyncChainsqlRootCA=0
SyncGenesisHeader=0
DepolyECCM=0

ChainSQLRPC="ws://127.0.0.1:6006"
ChainsqlChainID=1000
ChainSQLRootCA=""
ChainSQLClientCA=""
ChainSQLClientKey=""
ChainSQLServerName=""

function usage() {
    echo "setup [option]"
    echo 
    echo "usage:"
    echo "./setup.sh --poly_rpc_address http://127.0.0.1:20336 --chainsql_rpc_address ws://127.0.0.1:6006 
            --register_side_chain --sync_chain_root_ca --sync_genesis_header --deploy_eccm --chainsql_chain_id 1000"
    echo
    echo " Option"
    echo "   --poly_rpc_address url"
    echo "   --register_side_chain"
    echo "   --sync_chain_root_ca"
    echo "   --sync_genesis_header"
    echo "   --deploy_eccm"
    echo "   --chainsql_rpc_address url"
    echo "   --chainsql_chain_id id"
    echo "   --chainsql_root_ca ca_path"
    echo "   --chainsql_client_ca ca_path"
    echo "   --chainsql_client_key key_path"
    echo "   --chainsql_server_name name"
    echo
    exit
}

function require() {
    if [ "$1" != "0" ]; then
        printf "${RED}$2${NC}\n"
        exit 1
    fi
}

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --poly_rpc_address)
    RCRPCAddress=$2
    shift # past argument
    shift # past value
    ;;
    --register_side_chain)
    RegisterSideChain=1
    shift # past argument
    ;;
    --sync_chain_root_ca)
    SyncChainsqlRootCA=1
    shift # past argument
    ;;
    --sync_genesis_header)
    SyncGenesisHeader=1
    shift # past argument
    ;;
    --deploy_eccm)
    DepolyECCM=1
    shift # past argument
    ;;
    --chainsql_rpc_address)
    ChainSQLRPC=$2
    shift # past argument
    shift # past value
    ;;
    --chainsql_chain_id)
    ChainsqlChainID=$2
    shift # past argument
    shift # past value
    ;;
    --chainsql_root_ca)
    ChainSQLRootCA=$2
    shift # past argument
    shift # past value
    ;;
    --chainsql_client_ca)
    ChainSQLClientCA=$2
    shift # past argument
    shift # past value
    ;;
    --chainsql_client_key)
    ChainSQLClientKey=$2
    shift # past argument
    shift # past value
    ;;
    --chainsql_server_name)
    ChainSQLServerName=$2
    shift # past argument
    shift # past value
    ;;
    -h|--help)
    usage
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

echo "poly RPC: ${RCRPCAddress}"
echo "chainsql RPC: ${ChainSQLRPC}"
echo "chainsql chain id: ${ChainsqlChainID}"
echo "RegisterSideChain: ${RegisterSideChain}"
echo "SyncChainsqlRootCA: ${SyncChainsqlRootCA}"
echo "SyncGenesisHeader: ${SyncGenesisHeader}"
echo "DepolyECCM: ${DepolyECCM}"

if [ ! -f "chainsql_depolyer" ]; then
    printf "${RED}chainsql_depolyer dosen't exits${NC}\n"
    exit 100
fi

if [ ! -f "poly-tools" ]; then
    printf "${RED}poly-tools dosen't exits${NC}\n"
    exit 100
fi

cat > .wallet1.dat << EOF
{"name":"MyWallet","version":"1.1","scrypt":{"p":8,"n":16384,"r":8,"dkLen":64},"accounts":[{"address":"AaF8fkb3ZxiQxpK8ThDV23H3AdKSaqtW8D","enc-alg":"aes-256-gcm","key":"sOZ9Hvuk/wSH8yeWevnyIvGsdO/0BXMRFadtrGFMiLM/ZP0gtSpjf1neCXz3nnKz","algorithm":"ECDSA","salt":"zMU48RN+eCKYedyIam9FHg==","parameters":{"curve":""},"label":"","publicKey":"12050285de91f0fe7b8e7c50ab49261e8e14b8d65a641bd72d60b5aa95d218bb2c8dc7","signatureScheme":"SHA256withECDSA","isDefault":true,"lock":false}]}
EOF

cat > .wallet2.dat << EOF
{"name":"MyWallet","version":"1.1","scrypt":{"p":8,"n":16384,"r":8,"dkLen":64},"accounts":[{"address":"Adox6qM2CxfaQeds9JsFuGMu71ZNx2jDxu","enc-alg":"aes-256-gcm","key":"ACJZorP7x4YMs3yKfWz9OeTicnB9KFoQzciT1G0n0iB+vkcUQsS03I279FVZhjyl","algorithm":"ECDSA","salt":"Wy4lPOHq6RkgSrRQjRD3MA==","parameters":{"curve":""},"label":"","publicKey":"120503f9b96a946513186713a90936e5348411805af259cec2e143995b0fa28661b98a","signatureScheme":"SHA256withECDSA","isDefault":true,"lock":false}]}
EOF

cat > .wallet3.dat << EOF
{"name":"MyWallet","version":"1.1","scrypt":{"p":8,"n":16384,"r":8,"dkLen":64},"accounts":[{"address":"AG3uQqymPm6F6kgMXBAdakLbeEDbGAxHSy","enc-alg":"aes-256-gcm","key":"qvy22Ulx/otu4Iz6yixOffNR9uit35eYt2LX9MUw6MQtfcUaKzmCAp7zsf35Sr8V","algorithm":"ECDSA","salt":"QJqgcyQENVkPiuwTY1EcgA==","parameters":{"curve":""},"label":"","publicKey":"1205020c1c2d0da443b8fff03c0fd82a4f141eaf86b42329207a1e38b55804c56aade4","signatureScheme":"SHA256withECDSA","isDefault":true,"lock":false}]}
EOF

cat > .wallet4.dat << EOF
{"name":"MyWallet","version":"1.1","scrypt":{"p":8,"n":16384,"r":8,"dkLen":64},"accounts":[{"address":"AGMoakkvo7tu14kGfK7SzFsW4nNkqtEjtz","enc-alg":"aes-256-gcm","key":"q24Dknean4mmt63l98netjsJ7mqfgfli2qLRcvlznfkXBRWaw5SZ0BmTJii0XNpo","algorithm":"ECDSA","salt":"YPF5WCzvIUkH2/LRYtyFRw==","parameters":{"curve":""},"label":"","publicKey":"1205037d229c01217cd07b69595c7689ec3d81fa845915843ca035d3644dbd50703c1d","signatureScheme":"SHA256withECDSA","isDefault":true,"lock":false}]}
EOF

cat > .chainsql.json << EOF
{
    "URL": "${ChainSQLRPC}",
    "ServerName": "${ChainSQLServerName}",
    "RootCertPath":"${ChainSQLRootCA}",
    "ClientCertPath":"${ChainSQLClientCA}",
    "ClientKeyPath":"${ChainSQLClientKey}",
    "Account": {
        "Address":"zHb9CJAWyB4zj91VRWn96DkukG4bwdtyTh",
        "Secrect":"xnoPBzXtMeMyMHUVTgbuqAfg1SUTb"
    }
}
EOF

cat > .poly_tools_config.json << EOF
{
    "RCWallet": ".wallet1.dat",
    "RCWalletPwd": "${RCWalletPwd}",
    "RchainJsonRpcAddress": "${RCRPCAddress}",
    "RCEpoch": 0,
    "ReportInterval": 60,
    "ReportDir": "./report",
    "BatchTxNum": 1,
    "BatchInterval": 1,
    "TxNumPerBatch": 1,
    "ChainsqlCCMCHex":"",
    "ChainsqlCCMC":"",
    "ChainsqlSdkConfFile":".chainsql.json",
    "ChainsqlChainID":${ChainsqlChainID}
}
EOF

printf "${GREEN}Begin to generate CA for chaisnql-relayer${NC}\n"

if [ ! -d "certs" ]; then
    mkdir certs
fi

pwd=`pwd`
cd certs

if [ ! -f "openssl.conf" ]; then
    printf "${RED}openssl.conf dosen't exits, generating CA was failure.${NC}\n"
    exit 100
fi

if [ ! -f "rootCA.key" ]; then
    openssl ecparam -genkey -name secp256k1 -out rootCA.key
    require $? "Generating rootCA.key was failure"
    printf "${GREEN}generated rootCA.key${NC}\n"
fi


if [ ! -f "rootCA.crt" ]; then
    openssl req -new -x509 -nodes -sha256 -key rootCA.key -days 365 -out rootCA.crt
    require $? "Generating rootCA.crt was failure"
    printf "${GREEN}generated rootCA.crt${NC}\n"
fi

if [ ! -f "server.key" ]; then
    openssl ecparam -genkey -name secp256k1 -out rootCA.key
    require $? "Generating server.key was failure"

    openssl pkcs8 -topk8 -nocrypt -in server.key -out pkcs8.server.key
    printf "${GREEN}generated server.key${NC}\n"
fi

if [ ! -f "server.crt" ]; then
    if [ ! -f "server.csr" ]; then
        openssl req -config openssl.conf -new -nodes -sha256 -key server.key -out server.csr
        require $? "Generating server.csr was failure"
        printf "${GREEN}generated server.csr${NC}\n"
    fi

    openss x509 -req -extfile openssl.conf -extensions san_env -days 365 \
            -sha256 -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
            -out server.crt
    require $? "Generating server.crt was failure"
    printf "${GREEN}generated server.crt${NC}\n"
fi

cd ${pwd}

if [ ${DepolyECCM} -eq 1 ]; then
    printf "${GREEN}Start deploy eccm contracts ..${NC}\n"
    ./chainsql_depolyer -conf=.poly_tools_config.json > .output.txt
    require $? "Finished deploy eccm contracts was failure."
fi

if [ ! -f ".output.txt" ]; then
    printf " ${RED}ECCM haven't been deploied.${NC}\n"
    exit 1
fi

ChainsqlECCD=`cat .output.txt|head -n 1|awk '{print $7}'|awk -F "," '{print $1}'|awk -F ":" '{print $2}'`
ChainsqlECCM=`cat .output.txt|head -n 2|tail -n 1|awk '{print $7}'|awk -F "," '{print $1}'|awk -F ":" '{print $2}'`
ChainsqlECCMP=`cat .output.txt|tail -n 1|awk '{print $7}'|awk -F "," '{print $1}'|awk -F ":" '{print $2}'`

printf " ${CYAN}ECCD: ${ChainsqlECCD}${NC}\n"
printf " ${CYAN}ECCM: ${ChainsqlECCM}${NC}\n"
printf " ${CYAN}ECCMP: ${ChainsqlECCMP}${NC}\n"

cat > .poly_tools_config.json << EOF
{
    "RCWallet": ".wallet1.dat",
    "RCWalletPwd": "${RCWalletPwd}",
    "RchainJsonRpcAddress": "${RCRPCAddress}",
    "RCEpoch": 0,
    "ReportInterval": 60,
    "ReportDir": "./report",
    "BatchTxNum": 1,
    "BatchInterval": 1,
    "TxNumPerBatch": 1,
    "ChainsqlCCMCHex":"",
    "ChainsqlCCMC":"${ChainsqlECCM}",
    "ChainsqlSdkConfFile":".chainsql.json",
    "ChainsqlChainID":${ChainsqlChainID}
}
EOF
#cat .output.txt
printf "${GREEN}Finished deploy eccm contracts${NC}\n"
echo 
if [ ! -f ".wallet1.dat" ]; then
    echo ".wallet1.dat dosen't exits"
    exit 100
fi

if [ ${RegisterSideChain} -eq 1 ]; then
    printf "${GREEN}Start register side chain ..${NC}\n"
    ./poly-tools --conf=.poly_tools_config.json \
                -tool register_side_chain \
                -pwallets .wallet1.dat,.wallet2.dat,.wallet3.dat,.wallet4.dat \
                -ppwds ${RCWalletPwd},${RCWalletPwd},${RCWalletPwd},${RCWalletPwd} \
                --chainid ${ChainsqlChainID}
    echo
    require $? "Failed to register side chain."
    printf "${GREEN}Finished register side chain${NC}\n"
    echo 
fi

if [ ${SyncChainsqlRootCA} -eq 1 ]; then
    printf "${GREEN}Start sync chainsql root CA ...${NC}\n"
    if [ ! -f "./certs/rootCA.crt" ]; then
        echo "RootCA dosen't exists. [./certs/rootCA.crt]"
    else
        ./poly-tools --conf=.poly_tools_config.json \
                    -tool sync_chainsql_root_ca \
                    -pwallets .wallet1.dat,.wallet2.dat,.wallet3.dat,.wallet4.dat \
                    -ppwds ${RCWalletPwd},${RCWalletPwd},${RCWalletPwd},${RCWalletPwd} \
                    --chainid ${ChainsqlChainID} \
                    -rootca ./certs/rootCA.crt
    fi
    echo
    require $? "Failed to sync chainsql root CA."
    printf "${GREEN}Finished sync chainsql root CA.${NC}\n"
    echo 
fi

if [ ${SyncGenesisHeader} -eq 1 ]; then
    printf "${GREEN}Start sync poly's genesis block to chainsql ...${NC}\n"
    ./poly-tools --conf=.poly_tools_config.json \
                -tool sync_genesis_header \
                -pwallets .wallet1.dat,.wallet2.dat,.wallet3.dat,.wallet4.dat \
                -ppwds ${RCWalletPwd},${RCWalletPwd},${RCWalletPwd},${RCWalletPwd} \
                --chainid ${ChainsqlChainID}
    echo
    require $? "Failed to sync poly's genesis block to chainsql. "
    printf "${GREEN}Finished sync poly's genesis block to chainsql.${NC}\n"
fi

if [ ! -f "./chainsql-relayer" ]; then
    exit 0
fi

cat > .chainsql_relayer.json << EOF
{
    "PolyConfig": {
      "RestURL": "${RCRPCAddress}",
      "EntranceContractAddress": "0300000000000000000000000000000000000000",
      "WalletFile": ".wallet1.dat",
      "WalletPwd": "peersafe"
    },
    "ChainsqlConfig": {
      "SideChainId": ${ChainsqlChainID},
      "ECCMContractAddress": "${ChainsqlECCM}",
      "ECCDContractAddress": "${ChainsqlECCD}",
      "AgencyPath": "./certs/rootCA.crt",
      "NodePath": "./certs/server.crt",
      "KeyPath": "./certs/pkcs8.server.key",
      "IsGM": false
    },
    "BoltDbPath": "./boltdb"
 }
EOF

cat > chainsql-relayer.sh <<EOF
#!/bin/sh

if [ ! -d "./boltdb" ]; then
    mkdir boltdb
fi

./chainsql-relayer --loglevel 1 --config .chainsql_relayer.json --chainsql .chainsql.json  --poly 1 --chainsqlforce 1 > Log.txt &

EOF
chmod 755 chainsql-relayer.sh

printf "\n"
printf "Finished setup,be sure to execute the following commands for launching chainsql-relayer:\n"
printf " ${GREEN}./chainsql-relayer.sh${NC}\n"
printf "\n"