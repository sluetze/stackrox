package common

import "github.com/stackrox/rox/pkg/errox"

var (
	// ErrInvalidCommandOption indicates bad options provided by the user
	// during invocation of roxctl command.
	ErrInvalidCommandOption = errox.InvalidArgs.New("invalid command option")

	// ErrDeprecatedFlag is error factory for commands with deprecated flags.
	ErrDeprecatedFlag = func(oldFlag, newFlag string) errox.Error {
		return errox.InvalidArgs.Newf("specified deprecated flag %q and new flag %q at the same time", oldFlag, newFlag)
	}

	// ErrorOpenShiftMonitoringNotSupported indicates that the OpenShift monitoring flag
	// is not supported on OpenShift 3.
	ErrorOpenShiftMonitoringNotSupported = "The --openshift-monitoring flag is not supported for OpenShift 3. Set --openshift-version=4 to indicate that you are deploying on OpenShift 4.x in order to use this flag."
)
