// Code generated by "stringer -type=Resource"; DO NOT EDIT.

package metrics

import "strconv"

const _Resource_name = "AlertDeploymentProcessIndicatorImageSecretNamespaceNetworkPolicyNodeProviderMetadataComplianceReturnImageIntegrationServiceAccountRoleRoleBinding"

var _Resource_index = [...]uint8{0, 5, 15, 31, 36, 42, 51, 64, 68, 84, 100, 116, 130, 134, 145}

func (i Resource) String() string {
	if i < 0 || i >= Resource(len(_Resource_index)-1) {
		return "Resource(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Resource_name[_Resource_index[i]:_Resource_index[i+1]]
}
