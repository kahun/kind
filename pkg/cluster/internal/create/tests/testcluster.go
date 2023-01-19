package main

import (
	"fmt"
	"os"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/cluster"
)

func main() {
	descriptor, err := cluster.GetClusterDescriptor()
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	fmt.Println("Descriptor:", descriptor)

	manifest, err := cluster.GetClusterManifest(*descriptor)
	if err != nil {
		fmt.Println("\nError: ", err)
		os.Exit(1)
	}
	fmt.Println("\nManifest:\n\n", manifest)
}
