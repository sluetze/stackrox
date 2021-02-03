package fieldnames

var (
	numFields int
)

// This block enumerates all known field names.
var (
	AddCaps                       = newFieldName("Add Capabilities")
	CVE                           = newFieldName("CVE")
	CVSS                          = newFieldName("CVSS")
	ContainerCPULimit             = newFieldName("Container CPU Limit")
	ContainerCPURequest           = newFieldName("Container CPU Request")
	ContainerMemLimit             = newFieldName("Container Memory Limit")
	ContainerMemRequest           = newFieldName("Container Memory Request")
	ContainerName                 = newFieldName("Container Name")
	DisallowedAnnotation          = newFieldName("Disallowed Annotation")
	DisallowedImageLabel          = newFieldName("Disallowed Image Label")
	DockerfileLine                = newFieldName("Dockerfile Line")
	DropCaps                      = newFieldName("Drop Capabilities")
	EnvironmentVariable           = newFieldName("Environment Variable")
	ExposedNodePort               = newFieldName("Exposed Node Port")
	ExposedPort                   = newFieldName("Exposed Port")
	ExposedPortProtocol           = newFieldName("Exposed Port Protocol")
	FixedBy                       = newFieldName("Fixed By")
	HostIPC                       = newFieldName("Host IPC")
	HostNetwork                   = newFieldName("Host Network")
	HostPID                       = newFieldName("Host PID")
	ImageAge                      = newFieldName("Image Age")
	ImageComponent                = newFieldName("Image Component")
	ImageOS                       = newFieldName("Image OS")
	ImageRegistry                 = newFieldName("Image Registry")
	ImageRemote                   = newFieldName("Image Remote")
	ImageScanAge                  = newFieldName("Image Scan Age")
	ImageTag                      = newFieldName("Image Tag")
	ImageUser                     = newFieldName("Image User")
	MinimumRBACPermissions        = newFieldName("Minimum RBAC Permissions")
	MountPropagation              = newFieldName("Mount Propagation")
	Namespace                     = newFieldName("Namespace")
	PortExposure                  = newFieldName("Port Exposure Method")
	PrivilegedContainer           = newFieldName("Privileged Container")
	ProcessAncestor               = newFieldName("Process Ancestor")
	ProcessArguments              = newFieldName("Process Arguments")
	ProcessName                   = newFieldName("Process Name")
	ProcessUID                    = newFieldName("Process UID")
	ReadOnlyRootFS                = newFieldName("Read-Only Root Filesystem")
	RequiredAnnotation            = newFieldName("Required Annotation")
	RequiredImageLabel            = newFieldName("Required Image Label")
	RequiredLabel                 = newFieldName("Required Label")
	SeccompProfileType            = newFieldName("Seccomp Profile Type")
	ServiceAccount                = newFieldName("Service Account")
	UnexpectedNetworkFlowDetected = newFieldName("Unexpected Network Flow Detected")
	UnexpectedProcessExecuted     = newFieldName("Unexpected Process Executed")
	UnscannedImage                = newFieldName("Unscanned Image")
	VolumeDestination             = newFieldName("Volume Destination")
	VolumeName                    = newFieldName("Volume Name")
	VolumeSource                  = newFieldName("Volume Source")
	VolumeType                    = newFieldName("Volume Type")
	WritableHostMount             = newFieldName("Writable Host Mount")
	WritableMountedVolume         = newFieldName("Writable Mounted Volume")
	KubeResource                  = newFieldName("Kubernetes Resource")
	KubeAPIVerb                   = newFieldName("Kubernetes API Verb")
)

func newFieldName(field string) string {
	numFields++
	return field
}

// Count returns the number of known field names. It's useful for testing.
func Count() int {
	return numFields
}
