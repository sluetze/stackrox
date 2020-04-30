package services

import io.stackrox.proto.api.v1.Common
import io.stackrox.proto.api.v1.RoleServiceGrpc
import io.stackrox.proto.api.v1.RoleServiceOuterClass
import io.stackrox.proto.storage.RoleOuterClass.Role

class RoleService extends BaseService {
    static getRoleService() {
        return RoleServiceGrpc.newBlockingStub(getChannel())
    }

    static getRoles() {
        return getRoleService().getRoles(EMPTY)
    }

    static getRole(String roleId) {
        return getRoleService().getRole(Common.ResourceByID.newBuilder().setId(roleId).build())
    }

    static RoleServiceOuterClass.GetResourcesResponse getResources() {
        try {
            return getRoleService().getResources(EMPTY)
        } catch (Exception e) {
            println "Failed to fetch resources: ${e}"
        }
    }

    static createRole(Role role) {
        try {
            getRoleService().createRole(role)
        } catch (Exception e) {
            println "Failed to create role ${role.name}: ${e}"
        }
    }

    static deleteRole(String name) {
        try {
            getRoleService().deleteRole(Common.ResourceByID.newBuilder().setId(name).build())
        } catch (Exception e) {
            println "Error deleting role ${name}: ${e}"
        }
    }

    static myPermissions() {
        getRoleService().getMyPermissions(EMPTY)
    }
}

