######
### Root CA
######
create_root_ca()
{
    echo "Creating root CA..."
    mkdir -p "${BASE_PATH}/ca/root"
    cd "${BASE_PATH}/ca/root"
    mkdir -p certs crl newcerts private
    chmod 700 private
    touch index.txt
    echo 1000 > serial
    
    cat <<EOF > openssl.cnf
[ca]
default_ca = CA_default

[CA_default]
dir               = ${BASE_PATH}/ca/root
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem

crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[policy_strict]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca
prompt              = no

[req_distinguished_name]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = ${CC}
stateOrProvinceName             = ${STATE}
localityName                    = ${LOCALITY}
0.organizationName              = ${ORGANIZATION}
commonName                      = ${ROOT_CA_CN}
emailAddress                    = ${EMAIL}

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_intermediate_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[crl_ext]
authorityKeyIdentifier=keyid:always

[ocsp]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF


    echo "Creating root CA key..."
    openssl genrsa -aes256 -out private/ca.key.pem 4096
    chmod 600 private/ca.key.pem

    echo "Self signing root CA key..."
    openssl req \
          -config openssl.cnf \
          -key private/ca.key.pem \
          -new \
          -x509 \
          -days 7300 \
          -sha256 \
          -extensions v3_ca \
          -out certs/ca.cert.pem
}


######
### Intermediate CA
######
create_intermediate_ca() 
{
    echo "Creating intermediate CA..."
    mkdir -p "${BASE_PATH}/ca/intermediate"
    cd "${BASE_PATH}/ca/intermediate"
    mkdir -p certs crl csr newcerts private
    chmod 700 private
    touch index.txt
    echo 1000 > serial

    cat <<EOF > openssl.cnf
[ca]
default_ca = CA_default

[CA_default]
dir               = ${BASE_PATH}/ca/intermediate
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

private_key       = \$dir/private/intermediate.key.pem
certificate       = \$dir/certs/intermediate.cert.pem

crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

copy_extensions   = copy
unique_subject    = no
email_in_dn       = no

[policy_loose]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = server_cert
prompt              = no

[req_distinguished_name]
countryName                     = ${CC}
stateOrProvinceName             = ${STATE}
localityName                    = ${LOCALITY}
0.organizationName              = ${ORGANIZATION}
commonName                      = ${INTERMEDIATE_CA_CN}
emailAddress                    = ${EMAIL}

[usr_cert]
basicConstraints = critical,CA:FALSE
nsCertType = client, email
nsComment = "Signed"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[machine_cert]
basicConstraints = critical,CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Signed"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[crl_ext]
authorityKeyIdentifier=keyid:always

[ocsp]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF

    echo "Creating intermediate CA key..."
    openssl genrsa -aes256 -out private/intermediate.key.pem 4096
    chmod 600 private/intermediate.key.pem

    echo "Creating intermediate CA CSR..."
    openssl req \
          -config openssl.cnf \
          -new \
          -sha256 \
          -key private/intermediate.key.pem \
          -out csr/intermediate.csr.pem

    echo "Signing intermediate CA CSR with root CA key..."
    cd "${BASE_PATH}/ca"
    openssl ca \
          -config root/openssl.cnf \
          -extensions v3_intermediate_ca \
          -days 3650 \
          -notext \
          -md sha256 \
          -in intermediate/csr/intermediate.csr.pem \
          -out intermediate/certs/intermediate.cert.pem
    chmod 644 intermediate/certs/intermediate.cert.pem

    echo "Verifying intermediate CA certificate against root CA certificate..."
    openssl verify -CAfile root/certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

    echo "Creating intermediate CA certificate chain..."
    cat intermediate/certs/intermediate.cert.pem \
          root/certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
}

create_server_keypair()
{
    if [ -z "$1" ]
    then
      echo "No hostname specified"
      return
    fi
    local hostname=$1

    if [ -z "$2" ]
    then
      echo "No domainname specified"
      return
    fi
    local domain=$2
    local cn=${hostname}.${domain}

    echo "Creating server key (${hostname})..."
    mkdir -p "${BASE_PATH}/${hostname}"
    cd "${BASE_PATH}/${hostname}"
    if [ ! -f "openssl.cnf" ]
    then
    cat <<EOF > openssl.cnf
[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
req_extensions      = server_cert
prompt              = no

[req_distinguished_name]
countryName                     = ${CC}
stateOrProvinceName             = ${STATE}
localityName                    = ${LOCALITY}
0.organizationName              = ${ORGANIZATION}
commonName                      = ${cn}
emailAddress                    = ${EMAIL}

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${cn}
EOF
    fi

    mkdir -p certs private csr
    chmod 700 private
    openssl genrsa -out private/${cn}.key.pem 2048
    chmod 600 private/${cn}.key.pem

    echo "Creating ${hostname} CSR..."
    CN="DNS:${cn}" \
    openssl req \
          -config openssl.cnf \
          -new \
          -sha256 \
          -key private/${cn}.key.pem \
          -out csr/${cn}.csr.pem

    echo "Signing the ${hostname} CSR with intermediate CA key..."
    cd "${BASE_PATH}"
    openssl ca \
          -config ca/intermediate/openssl.cnf \
          -extensions server_cert \
          -days 375 \
          -notext \
          -md sha256 \
          -in ${hostname}/csr/${cn}.csr.pem \
          -out ${hostname}/certs/${cn}.cert.pem
    chmod 644 ${hostname}/certs/${cn}.cert.pem

    echo "Creating DC certificate chain..."
    cat ${hostname}/certs/${cn}.cert.pem \
        ca/intermediate/certs/intermediate.cert.pem > \
        ${hostname}/certs/${cn}-chain.cert.pem

    echo "Verifying DC certificate against intermediate CA certificate"
    openssl x509 -noout -text \
          -in ${hostname}/certs/${cn}.cert.pem

    echo "Creating PKCS#12 distributable key file..."
    openssl pkcs12 \
          -export \
          -chain \
          -inkey "${hostname}/private/${cn}.key.pem" \
          -in "${hostname}/certs/${cn}.cert.pem" \
          -certfile "ca/intermediate/certs/ca-chain.cert.pem" \
          -CAfile "ca/intermediate/certs/ca-chain.cert.pem" \
          -out "${hostname}/${cn}.p12" \
          -passout pass:
}

create_client_keypair()
{
    if [ -z "$1" ]
    then
      echo "No hostname specified"
      return
    fi
    local hostname=$1

    if [ -z "$2" ]
    then
      echo "No domainname specified"
      return
    fi
    local domain=$2
    local cn=${hostname}.${domain}

    echo "Creating client machine key (${hostname})..."
    mkdir -p "${BASE_PATH}/${hostname}"
    cd "${BASE_PATH}/${hostname}"
    if [ ! -f "openssl.cnf" ]
    then
    cat <<EOF > openssl.cnf
[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
req_extensions      = machine_cert
prompt              = no

[req_distinguished_name]
countryName                     = ${CC}
stateOrProvinceName             = ${STATE}
localityName                    = ${LOCALITY}
0.organizationName              = ${ORGANIZATION}
commonName                      = ${cn}
emailAddress                    = ${EMAIL}

[machine_cert]
basicConstraints = critical, CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:${cn}
EOF
    fi

    mkdir -p certs private csr
    chmod 700 private
    openssl genrsa -out private/${cn}.key.pem 2048
    chmod 600 private/${cn}.key.pem

    echo "Creating ${hostname} CSR..."
    CN="DNS:${cn}" \
    openssl req \
          -config openssl.cnf \
          -new \
          -sha256 \
          -key private/${cn}.key.pem \
          -out csr/${cn}.csr.pem

    echo "Signing the ${hostname} CSR with intermediate CA key..."
    cd "${BASE_PATH}"
    openssl ca \
          -config ca/intermediate/openssl.cnf \
          -extensions machine_cert \
          -days 375 \
          -notext \
          -md sha256 \
          -in ${hostname}/csr/${cn}.csr.pem \
          -out ${hostname}/certs/${cn}.cert.pem
    chmod 644 ${hostname}/certs/${cn}.cert.pem

    echo "Verifying machine certificate against intermediate CA certificate"
    openssl x509 -noout -text \
          -in ${hostname}/certs/${cn}.cert.pem

    echo "Creating machine certificate chain..."
    cat ${hostname}/certs/${cn}.cert.pem \
        ca/intermediate/certs/intermediate.cert.pem \
        ca/root/certs/ca.cert.pem > \
        ${hostname}/certs/${cn}-chain.cert.pem

    echo "Creating PKCS#12 distributable key file..."
    openssl pkcs12 \
          -export \
          -chain \
          -inkey "${hostname}/private/${cn}.key.pem" \
          -in "${hostname}/certs/${cn}.cert.pem" \
          -CAfile "ca/intermediate/certs/ca-chain.cert.pem" \
          -out "${hostname}/${cn}.p12" \
          -passout pass:iphone
}

create_user_keypair()
{
    if [ -z "$1" ]
    then
      echo "No username specified"
      return
    fi
    local username=$1

    if [ -z "$2" ]
    then
      echo "No domainname specified"
      return
    fi
    local domain=$2
    local cn="${username}@${domain}"

    echo "Creating user key (${cn})..."
    mkdir -p "${BASE_PATH}/${username}"
    cd "${BASE_PATH}/${username}"
    if [ ! -f "openssl.cnf" ]
    then
    cat <<EOF > openssl.cnf
[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
req_extensions      = usr_cert
prompt              = no

[req_distinguished_name]
countryName                     = ${CC}
stateOrProvinceName             = ${STATE}
localityName                    = ${LOCALITY}
0.organizationName              = ${ORGANIZATION}
commonName                      = ${cn}
emailAddress                    = ${cn}

[usr_cert]
basicConstraints = critical,CA:FALSE
nsCertType = client, email
nsComment = "Signed"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = email:copy
EOF
    fi

    mkdir -p certs private csr
    chmod 700 private
    openssl genrsa -out private/${username}.key.pem 2048
    chmod 600 private/${username}.key.pem

    echo "Creating ${username} CSR..."
    openssl req \
          -config openssl.cnf \
          -new \
          -sha256 \
          -key private/${username}.key.pem \
          -out csr/${username}.csr.pem
    if [ $? -ne 0 ]
    then
        return 127
    fi

    echo "Signing the ${username} CSR with intermediate CA key..."
    cd "${BASE_PATH}"
    openssl ca \
          -config ca/intermediate/openssl.cnf \
          -extensions usr_cert \
          -days 375 \
          -notext \
          -md sha256 \
          -in ${username}/csr/${username}.csr.pem \
          -out ${username}/certs/${username}.cert.pem
    if [ $? -ne 0 ]
    then
        return 127
    fi
    chmod 644 ${username}/certs/${username}.cert.pem

    echo "Verifying user certificate against intermediate CA certificate"
    openssl x509 -noout -text \
          -in ${username}/certs/${username}.cert.pem
    if [ $? -ne 0 ]
    then
        return 127
    fi

    echo "Creating user certificate chain..."
    cat ${username}/certs/${username}.cert.pem \
        ca/intermediate/certs/intermediate.cert.pem > \
        ${username}/certs/${username}-chain.cert.pem

    echo "Creating PKCS#12 distributable key file..."
    openssl pkcs12 \
          -export \
          -in "${username}/certs/${username}-chain.cert.pem" \
          -inkey "${username}/private/${username}.key.pem" \
          -certfile "ca/root/certs/ca.cert.pem" \
          -out "${username}/${username}.p12" \
          -passout pass:

    echo "Creating SSH public key..."
    ssh-keygen -f "${username}/private/${username}.key.pem" -y \
	    > "${username}/id_rsa.pub"
}

if [ ! -f "defaults" ]
then
	echo "no defaults file found..."
	exit 127
fi
. ./defaults

cd "${BASE_PATH}"
if [ ! \( -f "${BASE_PATH}/ca/root/private/ca.key.pem" -a -f "${BASE_PATH}/ca/root/certs/ca.cert.pem" \) ]
then
	create_root_ca
fi

#openssl x509 -noout -text -in "${BASE_PATH}/ca/root/certs/ca.cert.pem"
if [ ! \( -f "${BASE_PATH}/ca/intermediate/private/intermediate.key.pem" -a -f "${BASE_PATH}/ca/intermediate/certs/intermediate.cert.pem" \) ]
then
	create_intermediate_ca
fi

#openssl x509 -noout -text -in "${BASE_PATH}/ca/intermediate/certs/intermediate.cert.pem"
echo "Verifying intermediate CA certificate against root CA certificate..."
openssl verify -CAfile "${BASE_PATH}/ca/root/certs/ca.cert.pem" "${BASE_PATH}/ca/intermediate/certs/intermediate.cert.pem"
if [ ! $? -eq 0 ]
then
	create_intermediate_ca
fi

for SERVER in ${SERVERS}
do
	if [ ! \( -f "${BASE_PATH}/${SERVER}/private/${SERVER}.${DOMAIN}.key.pem" -a -f "${BASE_PATH}/${SERVER}/certs/${SERVER}.${DOMAIN}.cert.pem" \) ]
	then
		create_server_keypair "${SERVER}" "${DOMAIN}"
	fi

	echo "Verifying ${SERVER} certificate against root CA certificate..."
	openssl verify -CAfile "${BASE_PATH}/ca/intermediate/certs/ca-chain.cert.pem" "${BASE_PATH}/${SERVER}/certs/${SERVER}.${DOMAIN}.cert.pem"
	if [ ! $? -eq 0 ]
	then
		create_server_keypair "${SERVER}" "${DOMAIN}"
	fi
done

for CLIENT in ${CLIENTS}
do
        if [ ! \( -f "${BASE_PATH}/${CLIENT}/private/${CLIENT}.${DOMAIN}.key.pem" -a -f "${BASE_PATH}/${CLIENT}/certs/${CLIENT}.${DOMAIN}.cert.pem" \) ]
        then
                create_client_keypair "${CLIENT}" "${DOMAIN}"
        fi

        echo "Verifying ${CLIENT} certificate against root CA certificate..."
        openssl verify -CAfile "${BASE_PATH}/ca/intermediate/certs/ca-chain.cert.pem" "${BASE_PATH}/${CLIENT}/certs/${CLIENT}.${DOMAIN}.cert.pem"
        if [ ! $? -eq 0 ]
        then
                create_client_keypair "${CLIENT}" "${DOMAIN}"
        fi
done

for USER in ${USERS}
do
        if [ ! \( -f "${BASE_PATH}/${USER}/private/${USER}.key.pem" -a -f "${BASE_PATH}/${USER}/certs/${USER}.cert.pem" \) ]
        then
        	echo "${USER} certificate does not exist, creating..."
                create_user_keypair "${USER}" "${DOMAIN}"
        fi

        echo "Verifying ${USER} certificate against root CA certificate..."
        openssl verify -CAfile "${BASE_PATH}/ca/intermediate/certs/ca-chain.cert.pem" "${BASE_PATH}/${USER}/certs/${USER}.cert.pem"
        if [ ! $? -eq 0 ]
        then
                create_user_keypair "${USER}" "${DOMAIN}"
        fi
done
