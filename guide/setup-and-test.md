
## Setup environment

> https://hyperledger-fabric.readthedocs.io/en/release-2.5/prereqs.html#linux

- Install dependencies
    - Git
    - cURL
    - [Docker](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04)
    - openssl
    - libopenssl-dev
    - Go
        - https://go.dev/dl/go1.20.6.linux-amd64.tar.gz
        - https://go.dev/doc/install
    - JQ: `sudo apt-get install jq.`
    - SoftHSM (v2.5)
        - https://dist.opendnssec.org/source/softhsm-2.5.0.tar.gz
        - https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2
        - https://hyperledger-fabric.readthedocs.io/en/release-2.5/dev-setup/devenv.html#configure-softhsm
        - SoftHSM configuration typically involves copying /etc/softhsm/softhsm2.conf to $HOME/.config/softhsm2/softhsm2.conf and changing directories.tokendir to an appropriate location. Please see the man page for softhsm2.conf for details.
    - gnu-make and C compiler
        - `sudo apt install build-essential`
- Install the development tools
    - By default, these tools will be installed into `$HOME/go/bin` (run `mkdir -p $HOME/go/bin`)
    - update the ~/.bashrc (~/.zshrc)
        - add to the file: `export PATH=$PATH:$HOME/go/bin`
        - run `source ~/.bashrc`

## Build the fabric

- cd to the fabric folder
- run `make dist-clean all`

## Test networks

> https://github.com/hyperledger/fabric-samples/tree/main/test-network
> https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html#bring-up-the-test-network

- clone the repo `https://github.com/hyperledger/fabric-samples/`
- `cd fabric-samples/test-network`
- update the docker image of these files
    - https://github.com/hyperledger/fabric-samples/blob/main/test-network/compose/docker/docker-compose-test-net.yaml
    - https://github.com/hyperledger/fabric-samples/blob/main/test-network/compose/compose-test-net.yaml#L21
    - **TODO: give example files**
- brings down 
    - `./network.sh down`
- creates a Fabric network that consists of two peer nodes, one ordering node
    - `./network.sh up`
