#!/bin/sh

pwd=`pwd`

if [ ! -d "bin" ]; then
   mkdir -p bin/boltdb
   mkdir -p bin/poly
fi

# build chainsql-relayer
./build.sh

cd bin

if [ ! -f "config.json" ]; then
   ln -s ../config.json config.json
fi

if [ ! -f "chainsql.json" ]; then
   ln -s ../chainsql.json chainsql.json
fi

if [ -f "rootCA.key" ]; then
   exit 0
fi

# generate CA
openssl ecparam -genkey -name secp256k1 -out rootCA.key
openssl req -new -x509 -nodes -sha256 -key rootCA.key -days 365 -out rootCA.crt

# generate Self-Signed Certificates using OpenSSL
openssl ecparam -genkey -name secp256k1 -out server.key

openssl req -config openssl.conf -new -nodes -sha256 -key server.key -out server.csr
openssl x509 -req -extfile openssl.conf -extensions san_env -days 365 -sha256 -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt
openssl pkcs8 -topk8 -nocrypt -in server.key -out pkcs8.server.key

cat > chainsql-relayer.sh <<EOF

#!/bin/sh

./chainsql-relayer --loglevel 1 --config ./config.json --chainsql ./chainsql.json  --poly 6194 --chainsqlforce 110

EOF


chmod 755 chainsql-relayer.sh

cd poly

cat > wallet.dat <<EOF
{"name":"MyWallet","version":"1.1","scrypt":{"p":8,"n":16384,"r":8,"dkLen":64},"accounts":[{"address":"AaF8fkb3ZxiQxpK8ThDV23H3AdKSaqtW8D","enc-alg":"aes-256-gcm","key":"sOZ9Hvuk/wSH8yeWevnyIvGsdO/0BXMRFadtrGFMiLM/ZP0gtSpjf1neCXz3nnKz","algorithm":"ECDSA","salt":"zMU48RN+eCKYedyIam9FHg==","parameters":{"curve":""},"label":"","publicKey":"12050285de91f0fe7b8e7c50ab49261e8e14b8d65a641bd72d60b5aa95d218bb2c8dc7","signatureScheme":"SHA256withECDSA","isDefault":true,"lock":false},{"address":"AMFRaPvuHMz3bAJM8F1d4kGZNya3af8PGw","enc-alg":"aes-256-gcm","key":"lHTqMFRXj+HKnDXISS2Ry+VZ6/eZFbDxzvnhzlVemFZLFK2t5e//OsFVA/fUFAp5","algorithm":"ECDSA","salt":"eLxERr7J3snaR7/YEP9vYw==","parameters":{"curve":"P-256"},"label":"","publicKey":"02645595a405c62594b66f1889e8f57ff2fed061cba42626e144eb2a9ee172dafb","signatureScheme":"SHA256withECDSA","isDefault":false,"lock":false}]}
EOF

cd ${pwd}
