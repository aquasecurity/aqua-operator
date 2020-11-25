package controller

import (
	"github.com/aquasecurity/aqua-operator/pkg/controller/aquakubeenforcer"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, aquakubeenforcer.Add)
}
