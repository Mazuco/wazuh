#!/bin/bash

# Para o script se ocorrer algum erro
set -e

echo ">>> [1/7] Iniciando configuracao para Rocky Linux 9..."

# 1. Desabilitar SELinux (Essencial para driver none)
echo ">>> Desabilitando SELinux..."
setenforce 0 || true
sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

# 2. Instalar Docker e Dependencias
echo ">>> [2/7] Instalando Docker e dependencias..."
dnf remove -y podman buildah docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
dnf install -y dnf-utils conntrack git socat
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin --allowerasing

systemctl start docker
systemctl enable docker

# 3. Instalar CNI Plugins (A PARTE QUE FALTAVA)
# O driver 'none' exige isso em /opt/cni/bin
echo ">>> [3/7] Instalando CNI Plugins (Obrigatorio)..."
CNI_PLUGIN_VERSION="v1.6.0"
CNI_ARCH="amd64"
wget "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-linux-${CNI_ARCH}-${CNI_PLUGIN_VERSION}.tgz"
mkdir -p /opt/cni/bin
tar -xzvf cni-plugins-linux-${CNI_ARCH}-${CNI_PLUGIN_VERSION}.tgz -C /opt/cni/bin
rm -f cni-plugins-linux-${CNI_ARCH}-${CNI_PLUGIN_VERSION}.tgz

# 4. Instalar Kubectl
KUBECTL_VERSION="v1.35.0"
echo ">>> [4/7] Instalando Kubectl $KUBECTL_VERSION..."
curl -LO https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl
chmod +x kubectl
mv kubectl /usr/local/bin/

# 5. Instalar Minikube
echo ">>> [5/7] Instalando Minikube..."
curl -Lo minikube https://github.com/kubernetes/minikube/releases/latest/download/minikube-linux-amd64
chmod +x minikube
mv minikube /usr/local/bin/

# 6. Instalar crictl
CRICTL_VERSION="v1.32.0"
echo ">>> [6/7] Instalando crictl $CRICTL_VERSION..."
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$CRICTL_VERSION/crictl-$CRICTL_VERSION-linux-amd64.tar.gz
tar zxvf crictl-$CRICTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin/
rm -f crictl-$CRICTL_VERSION-linux-amd64.tar.gz

# 7. Instalar cri-dockerd (Via Binário para evitar erro do libcgroup)
CRI_DOCKERD_VERSION="0.3.16"
echo ">>> [7/7] Instalando cri-dockerd v${CRI_DOCKERD_VERSION}..."

# Limpeza preventiva
systemctl stop cri-docker.service cri-docker.socket || true
rm -f /usr/local/bin/cri-dockerd

wget https://github.com/Mirantis/cri-dockerd/releases/download/v${CRI_DOCKERD_VERSION}/cri-dockerd-${CRI_DOCKERD_VERSION}.amd64.tgz
tar xvf cri-dockerd-${CRI_DOCKERD_VERSION}.amd64.tgz
mv cri-dockerd/cri-dockerd /usr/local/bin/
rm -rf cri-dockerd cri-dockerd-${CRI_DOCKERD_VERSION}.amd64.tgz

wget -O /etc/systemd/system/cri-docker.service https://raw.githubusercontent.com/Mirantis/cri-dockerd/master/packaging/systemd/cri-docker.service
wget -O /etc/systemd/system/cri-docker.socket https://raw.githubusercontent.com/Mirantis/cri-dockerd/master/packaging/systemd/cri-docker.socket
sed -i -e 's,/usr/bin/cri-dockerd,/usr/local/bin/cri-dockerd,' /etc/systemd/system/cri-docker.service

systemctl daemon-reload
systemctl enable cri-docker.service
systemctl enable --now cri-docker.socket

# Configuração Extra para crictl
cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/cri-dockerd.sock
image-endpoint: unix:///var/run/cri-dockerd.sock
timeout: 10
debug: false
EOF

echo ">>> Instalacao concluida! Agora voce pode rodar o 'minikube start'"


