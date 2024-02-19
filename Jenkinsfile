@Library('libpipelines') _

hose {
    EMAIL = 'clouds-integration@stratio.com'
    BUILDTOOL = 'make'
    DEVTIMEOUT = 30
    BUILDTOOL_IMAGE = 'golang:1.20'
    ANCHORE_POLICY = "production"
    VERSIONING_TYPE = 'stratioVersion-3-3'
    UPSTREAM_VERSION = '0.17.0'
    DEPLOYONPRS = true
    GRYPE_TEST = true
    MODULE_LIST = [ "paas.cloud-provisioner:cloud-provisioner:tar.gz"]

    DEV = { config ->
        doPackage(conf: config, parameters: "GOCACHE=/tmp")
        doDeploy(conf: config)
        doCustomStage(conf:config, buildToolOverride: [CUSTOM_COMMAND: 'mkdir -p CTS/resources; tar zxvf bin/cloud-provisioner.tar.gz -C CTS/resources/; chmod -R 0700 CTS/resources/bin/cloud-provisioner'], stageName: "Extract binary")
        doGrypeScan(conf: config, artifactsList: [[path: 'CTS/resources/bin/cloud-provisioner', name: 'cloud-provisioner']])
    }
    BUILDTOOL_MEMORY_REQUEST = "1024Mi"
    BUILDTOOL_MEMORY_LIMIT = "4096Mi"

    DOC = { config ->
        doStratioDocsChecks(conf: config)
    }
}
