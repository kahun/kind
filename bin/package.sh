#!/bin/bash -e

DIR=bin
BASEDIR=`dirname $0`/../..
VERSION=$1
EXTENSION="tar.gz"

if [ -d "$DIR" ] || [ -r "$DIR"/cloud-provisioner]; then
	echo "Packaging cloud-provisioner-$VERSION..."
	tar czf "$DIR"/cloud-provisioner-${VERSION}.${EXTENSION} "$DIR"/cloud-provisioner

	echo "Packaging upgrade-provisioner-$VERSION..."
	tar czf "$DIR"/upgrade-provisioner-${VERSION}.${EXTENSION} scripts/upgrade-provisioner.py
else
	echo "Run 'make build' first"
	exit 1
fi

