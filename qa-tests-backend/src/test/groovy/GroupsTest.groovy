import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.stackrox.proto.api.v1.GroupServiceOuterClass.GetGroupsRequest
import io.stackrox.proto.storage.GroupOuterClass.Group
import io.stackrox.proto.storage.GroupOuterClass.GroupProperties
import services.GroupService
import spock.lang.Unroll

class GroupsTest extends BaseSpecification {

    private static final PROVIDERS = [
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString(),
    ]

    private static final GROUPS = [
            Group.newBuilder()
                    .setRoleName("QAGroupTest-Group0")
                    .build(),
            Group.newBuilder()
                    .setRoleName("QAGroupTest-Group1")
                    .setProps(GroupProperties.newBuilder()
                        .setAuthProviderId(PROVIDERS[0])
                        .build())
                    .build(),
            Group.newBuilder()
                    .setRoleName("QAGroupTest-Group2")
                    .setProps(GroupProperties.newBuilder()
                        .setAuthProviderId(PROVIDERS[0])
                        .setKey("foo")
                        .setValue("bar")
                        .build())
                    .build(),
            Group.newBuilder()
                    .setRoleName("QAGroupTest-Group3")
                    .setProps(GroupProperties.newBuilder()
                        .setAuthProviderId(PROVIDERS[1])
                        .setKey("foo")
                        .setValue("bar")
                        .build())
                    .build(),
    ]

    def setupSpec() {
        for (def group : GROUPS) {
            GroupService.createGroup(group)
        }
    }

    def cleanupSpec() {
        for (def group : GROUPS) {
            try {
                GroupService.deleteGroup(group.props)
            } catch (Exception ex) {
                print "Failed to delete group: ${ex.message}"
            }
        }
    }

    @Unroll
    def "Test that GetGroup and GetGroups work correctly with query args (#authProviderId, #key, #value)"() {
        when:
        "A query is made for GetGroup and GetGroups with the given params"
        def propsBuilder = GroupProperties.newBuilder()
        def reqBuilder = GetGroupsRequest.newBuilder()
        if (authProviderId != null) {
            propsBuilder.setAuthProviderId(PROVIDERS[authProviderId])
            reqBuilder.setAuthProviderId(PROVIDERS[authProviderId])
        }
        if (key != null) {
            propsBuilder.setKey(key)
            reqBuilder.setKey(key)
        }
        if (value != null) {
            propsBuilder.setValue(value)
            propsBuilder.setValue(value)
        }

        String matchedGroup = null
        try {
            def grp = GroupService.getGroup(propsBuilder.build())
            if (grp.roleName.startsWith("QAGroupTest-")) {
                matchedGroup = grp.roleName["QAGroupTest-".length()..-1]
            }
        } catch (StatusRuntimeException ex) {
            if (ex.status.code != Status.Code.NOT_FOUND) {
                throw ex
            }
        }
        def matchedGroups = GroupService.getGroups(reqBuilder.build()).groupsList*.roleName.collectMany {
            return it.startsWith("QAGroupTest-") ? [it["QAGroupTest-".length()..-1]] : []
        }.sort()

        then:
        "Results should match the expected data"
        assert expectGroup == matchedGroup
        assert expectGroups == matchedGroups

        where:
        "Data inputs are"
        authProviderId | key   | value | expectGroup | expectGroups
        null           | null  | null  | "Group0"    | ["Group0", "Group1", "Group2", "Group3"]
        0              | null  | null  | "Group1"    | ["Group1", "Group2"]
        null           | "foo" | "bar" | null        | ["Group2", "Group3"]
        0              | "foo" | "bar" | "Group2"    | ["Group2"]
        1              | null  | null  | null        | ["Group3"]
        1              | "foo" | "bar" | "Group3"    | ["Group3"]
    }
}
