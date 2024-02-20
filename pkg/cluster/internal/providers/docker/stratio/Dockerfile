ARG DOCKER_REG=docker.io
ARG IMAGE_VERSION=v1.27.0
FROM ${DOCKER_REG}/kindest/node:${IMAGE_VERSION}

# Init feature gates
ENV CLUSTER_TOPOLOGY=true
ENV CLUSTERCTL_DISABLE_VERSIONCHECK=true

# Tools versions
ENV CLUSTERCTL=v1.5.3
ENV CLUSTERAWSADM=v2.2.1
ENV HELM=v3.13.1

# Helm charts
ENV HELM_EXPERIMENTAL_OCI=1
ENV CLOUD_PROVIDER_AWS_CHART=0.0.8
ENV AWS_EBS_CSI_DRIVER_CHART=v2.20.0
ENV AZUREDISK_CSI_DRIVER_CHART=v1.28.3
ENV AZUREFILE_CSI_DRIVER_CHART=v1.28.3
ENV CLOUD_PROVIDER_AZURE_CHART=v1.26.7
ENV CLUSTER_AUTOSCALER_CHART=9.29.1
ENV TIGERA_OPERATOR_CHART=v3.26.1
ENV CERT_MANAGER_CHART_VERSION=v1.12.3

# Cluster-api artifacts
ENV CAPI_REPO=/root/.cluster-api/local-repository
ENV CAPA=v2.2.1
ENV CAPG=v1.4.0
ENV CAPZ=v1.11.4

# Install vim
RUN apt-get update && apt-get install -y \
  vim python3-pip git \
  && rm -rf /var/lib/apt/lists/*

# Add aliases
RUN echo 'alias k="kubectl"' >> ~/.bash_aliases \
    && echo 'alias capi-logs="kubectl -n capi-system logs -f deploy/capi-controller-manager"' >> ~/.bash_aliases \
    && echo 'alias capa-logs="kubectl -n capa-system logs -f deploy/capa-controller-manager"' >> ~/.bash_aliases \
    && echo 'alias capg-logs="kubectl -n capg-system logs -f deploy/capg-controller-manager"' >> ~/.bash_aliases \
    && echo 'alias capz-logs="kubectl -n capz-system logs -f deploy/capz-controller-manager"' >> ~/.bash_aliases \
    && echo 'alias kc-logs="kubectl -n kube-system logs -f deploy/keoscluster-controller-manager"' >> ~/.bash_aliases \
    && echo 'alias kw="kubectl --kubeconfig /kind/worker-cluster.kubeconfig"' >> ~/.bash_aliases

# Download clusterctl
RUN curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL}/clusterctl-linux-amd64 -o /usr/local/bin/clusterctl \
    && chmod +x /usr/local/bin/clusterctl

# Download clusterawsadm
RUN curl -L https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/download/${CLUSTERAWSADM}/clusterawsadm-linux-amd64 -o /usr/local/bin/clusterawsadm \
    && chmod +x /usr/local/bin/clusterawsadm

# Download helm
RUN curl -L https://get.helm.sh/helm-${HELM}-linux-amd64.tar.gz -o /root/helm.tar.gz \
  && tar -xf /root/helm.tar.gz -C /root && mv /root/linux-amd64/helm /usr/local/bin/helm \
  && rm -rf /root/linux-amd64 /root/helm.tar.gz \
  && chmod +x /usr/local/bin/helm \
  && helm plugin install https://github.com/hypnoglow/helm-s3.git

RUN mkdir -p ${CAPI_REPO}/cert-manager/${CERT_MANAGER_CHART_VERSION} \
    && curl -LJ -o ${CAPI_REPO}/cert-manager/${CERT_MANAGER_CHART_VERSION}/cert-manager.crds.yaml  https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.crds.yaml
  
# Download helm charts
RUN mkdir -p /stratio/helm \
  && for i in $(seq 1 3); do timeout 5 helm pull aws-cloud-controller-manager --version ${CLOUD_PROVIDER_AWS_CHART} --repo https://kubernetes.github.io/cloud-provider-aws --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull aws-ebs-csi-driver --version ${AWS_EBS_CSI_DRIVER_CHART} --repo https://kubernetes-sigs.github.io/aws-ebs-csi-driver --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull azuredisk-csi-driver --version ${AZUREDISK_CSI_DRIVER_CHART} --repo https://raw.githubusercontent.com/kubernetes-sigs/azuredisk-csi-driver/master/charts --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull azurefile-csi-driver --version ${AZUREFILE_CSI_DRIVER_CHART} --repo https://raw.githubusercontent.com/kubernetes-sigs/azurefile-csi-driver/master/charts --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull cloud-provider-azure --version ${CLOUD_PROVIDER_AZURE_CHART} --repo https://raw.githubusercontent.com/kubernetes-sigs/cloud-provider-azure/master/helm/repo --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull cluster-autoscaler --version ${CLUSTER_AUTOSCALER_CHART} --repo https://kubernetes.github.io/autoscaler --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull tigera-operator --version ${TIGERA_OPERATOR_CHART} --repo https://docs.projectcalico.org/charts --untar --untardir /stratio/helm && break; done \
  && for i in $(seq 1 3); do timeout 5 helm pull cert-manager --version ${CERT_MANAGER_CHART_VERSION} --repo  https://charts.jetstack.io --untar --untardir /stratio/helm && break; done

# Prepare cluster-api private repository
RUN mkdir -p ${CAPI_REPO}/infrastructure-aws/${CAPA} ${CAPI_REPO}/infrastructure-gcp/${CAPG} ${CAPI_REPO}/infrastructure-azure/${CAPZ} ${CAPI_REPO}/cluster-api/${CLUSTERCTL} ${CAPI_REPO}/bootstrap-kubeadm/${CLUSTERCTL} ${CAPI_REPO}/control-plane-kubeadm/${CLUSTERCTL} ${CROSSPLANE_CACHE} \
  && echo "providers:" > /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: aws\n    url: ${CAPI_REPO}/infrastructure-aws/${CAPA}/infrastructure-components.yaml\n    type: InfrastructureProvider" >> /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: gcp\n    url: ${CAPI_REPO}/infrastructure-gcp/${CAPG}/infrastructure-components.yaml\n    type: InfrastructureProvider" >> /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: azure\n    url: ${CAPI_REPO}/infrastructure-azure/${CAPZ}/infrastructure-components.yaml\n    type: InfrastructureProvider" >> /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: kubeadm\n    url: ${CAPI_REPO}/bootstrap-kubeadm/${CLUSTERCTL}/bootstrap-components.yaml\n    type: BootstrapProvider" >> /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: kubeadm\n    url: ${CAPI_REPO}/control-plane-kubeadm/${CLUSTERCTL}/control-plane-components.yaml\n    type: ControlPlaneProvider" >> /root/.cluster-api/clusterctl.yaml \
  && echo "  - name: cluster-api\n    url: ${CAPI_REPO}/cluster-api/${CLUSTERCTL}/core-components.yaml\n    type: CoreProvider" >> /root/.cluster-api/clusterctl.yaml

# Download cluster-api artifacts
RUN for i in metadata.yaml infrastructure-components.yaml; do \
      curl -L https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/download/${CAPA}/${i} -o ${CAPI_REPO}/infrastructure-aws/${CAPA}/${i} \
      && curl -L https://github.com/kubernetes-sigs/cluster-api-provider-gcp/releases/download/${CAPG}/${i} -o ${CAPI_REPO}/infrastructure-gcp/${CAPG}/${i} \
      && curl -L https://github.com/kubernetes-sigs/cluster-api-provider-azure/releases/download/${CAPZ}/${i} -o ${CAPI_REPO}/infrastructure-azure/${CAPZ}/${i}; done

RUN curl -L  https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL}/core-components.yaml -o ${CAPI_REPO}/cluster-api/${CLUSTERCTL}/core-components.yaml \
    && curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL}/bootstrap-components.yaml -o ${CAPI_REPO}/bootstrap-kubeadm/${CLUSTERCTL}/bootstrap-components.yaml \
    && curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL}/control-plane-components.yaml -o ${CAPI_REPO}/control-plane-kubeadm/${CLUSTERCTL}/control-plane-components.yaml \
    && curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL}/metadata.yaml -o ${CAPI_REPO}/cluster-api/${CLUSTERCTL}/metadata.yaml \
    && cp ${CAPI_REPO}/cluster-api/${CLUSTERCTL}/metadata.yaml ${CAPI_REPO}/bootstrap-kubeadm/${CLUSTERCTL}/metadata.yaml \
    && cp ${CAPI_REPO}/cluster-api/${CLUSTERCTL}/metadata.yaml ${CAPI_REPO}/control-plane-kubeadm/${CLUSTERCTL}/metadata.yaml
