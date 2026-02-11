#!/bin/bash

# Disable SELinux
setenforce 0
sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

# Install Docker
dnf install dnf-utils -y
dnf-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y --allowerasing
systemctl start docker
systemctl enable docker

# Install conntrack
dnf install conntrack -y

# Install Kubectl
curl -LO https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl
chmod +x kubectl
mv kubectl /usr/bin/

# Install Minikube
curl -Lo minikube https://github.com/kubernetes/minikube/releases/download/v1.38.0/minikube-linux-amd64
chmod +x minikube
mv minikube /usr/bin/

# Install crictl
VERSION="v1.35.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/bin/
rm -f crictl-$VERSION-linux-amd64.tar.gz

# Install cricd
wget https://github.com/Mirantis/cri-dockerd/releases/download/v0.2.6/cri-dockerd-0.2.6-3.el8.x86_64.rpm
rpm -i cri-dockerd-0.2.6-3.el8.x86_64.rpm 
rm cri-dockerd-0.2.6-3.el8.x86_64.rpm

# Start Minikube
minikube start --driver=none
