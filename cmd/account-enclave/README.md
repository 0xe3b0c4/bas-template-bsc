# The Account Enclaves command

account-enclave is a external signer used to sign the transactions. TEE environment powered by [AWS Nitro Enclaves](https://aws.amazon.com/en/ec2/nitro/nitro-enclaves/).

## Requirements

OS: Amaze Linux 2

Cloud Service:

1. AWS Nitro Enclaves
2. AWS KMS
3. AWS Secrets Manager

> private key is stored in AWS Secrets Manager, encrypted by AWS KMS.

> **instance rold need add AmazonEC2RoleforSSM policy.**

> *Account Enclave only Unseal single account*

tools: 

1. vsock-proxy
2. nitro-enclaves-allocator

## Usage

Configure Nitro Enclaves environment.

```shell
# update system
yum update -y

# install docker
amazon-linux-extras install docker
systemctl start docker
systemctl enable docker

# install aws-nitro-enclaves-cli 
amazon-linux-extras enable aws-nitro-enclaves-cli
yum install -y aws-nitro-enclaves-cli

# start nitro-enclaves-allocator and vsock-proxy
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service

systemctl start nitro-enclaves-vsock-proxy.service
systemctl enable nitro-enclaves-vsock-proxy.service
```

Clone the project.

```shell
git clone https://github.com/antimatter-dao/bas-genesis-config.git
cd bas-genesis-config
```

Build the docker image (in the project directory).

```shell
sudo docker build -t account-enclave:latest -f Dockerfile.enclaves .
```

Create EIF file.

```shell
sudo nitro-cli build-enclave --docker-uri account-enclave:latest --output-file /opt/account-enclave.eif
```

Run the enclave.

```shell
sudo nitro-cli run-enclave --enclave-name account-enclave --cpu-count 2 --memory 1024Mib --eif-path /opt/account-enclave.eif --enclave-cid 16
```

Unseal account. (in the host node)

```shell
# Unseal account
account-enclave unseal --daemon --aws.sm.region <REGION> --aws.sm.arn <SECRET_ARN> vsock://<CID>:<PORT>
```

command arguments:

- `--daemon` : run as a daemon, poll account state, keep account Unseal, if enclaves restart, Unseal account again.
- `--aws.sm.region <REGION>` : the region of the AWS Secrets Manager
- `--aws.sm.secret-id <SECRET_ARN>` : the private key id of the AWS Secrets Manager


Now, modify the host node start command

> host node use ec2 instance role to access AWS KMS and AWS Secrets Manager. (get the session token of the instance role)

- `--signer vsock://16:8545` : use the enclave as the signer (format `vsock://<CID>:<PORT>`, the CID is the enclave CID, the port is fixed to 8545)