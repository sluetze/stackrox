package networkgraph

const (
	// InternetExternalSourceID is UUID for network nodes external to a cluster which are not identified by CIDR block or IP address.
	InternetExternalSourceID = "afa12424-bde3-4313-b810-bb463cbe8f90"
	// InternalUnknownSourceID is UUID for network nodes internal to a cluster which are unable to be identified.
	InternalUnknownSourceID = "cfc24848-bde3-4313-b810-bb463cbe8f90"
	// InternetExternalSourceName is name for the Internet network node
	InternetExternalSourceName = "External Entities"
	// InternalUnknownSourceName is name for the internal-unknown network node
	InternalUnknownSourceName = "Internal Unknown Entities"
)
