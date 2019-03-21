# FROM sconecuratedimages/crosscompilers:releasecandidate
FROM ubuntu:16.04

# RUN sed -i 's/security\./old-releases\./g' /etc/apt/sources.list && sed -i 's/archive\./old-releases\./g' /etc/apt/sources.list

RUN apt-get update
RUN apt-get install -y --no-install-recommends coreutils git wget openssh-client build-essential cmake libssl-dev libprotobuf-dev autoconf libtool libprotobuf-c-dev protobuf-c-compiler ca-certificates automake pkgconf

# Graphene requirements
RUN apt-get install -y --no-install-recommends  python gawk python-protobuf python-crypto socat

# Install kernel headers so that Graphene can build the kernel module
# inside the container. The driver built inside the container is not
# actually used. The particular kernel version should not matter - just
# install a recent version.

RUN apt-get install -y --no-install-recommends linux-headers-4.4.0-141-generic

# SCONE requirements
RUN apt-get install -y --no-install-recommends libprotoc-dev pkgconf protobuf-compiler # to compile libprotobuf-c
# SGX-LKL
RUN apt-get install -y --no-install-recommends curl sudo make gcc bc python xutils-dev iproute2 iptables
RUN wget https://download.01.org/intel-sgx/linux-2.0/sgx_linux_ubuntu16.04.1_x64_sdk_2.0.100.40950.bin
RUN printf 'no\n/opt/intel\n' | bash ./sgx_linux_ubuntu16.04.1_x64_sdk_2.0.100.40950.bin
RUN wget https://download.01.org/intel-sgx/linux-2.0/sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin
RUN echo "43c43\n<             exit 4\n---\n>             #exit 4" | patch -p0 sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin
RUN yes no /opt/intel | bash ./sgx_linux_ubuntu16.04.1_x64_psw_2.0.100.40950.bin

RUN echo 'Defaults env_keep += "http_proxy https_proxy no_proxy"' >> /etc/sudoers
