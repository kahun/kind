#!/bin/bash -e

DIR=bin
BASEDIR=`dirname $0`/../..
VERSION=$1
EXTENSION="tar.gz"

if [ -d "$DIR" ] || [ -r "$DIR"/cloud-provisioner]; then
	echo "Packaging cloud-provisioner-$VERSION..."
	tar czf "$DIR"/cloud-provisioner-${VERSION}.${EXTENSION} "$DIR"/cloud-provisioner
else
	echo "Run 'make build' first"
	exit 1
fi

DIR=docs/descriptor
EXTENSION="yaml"
echo "Packaging keoscluster_v1beta1_template-$VERSION..."
cp "$DIR"/keoscluster_v1beta1_template.${EXTENSION} "$DIR"/keoscluster_v1beta1_template-${VERSION}.${EXTENSION}