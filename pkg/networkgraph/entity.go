package networkgraph

import (
	"github.com/stackrox/rox/generated/storage"
)

// Entity represents a network entity in a form that is suitable for use as a map key.
type Entity struct {
	Type storage.NetworkEntityInfo_Type
	ID   string
}

// ToProto converts the Entity struct to a storage.NetworkEntityInfo proto.
func (e Entity) ToProto() *storage.NetworkEntityInfo {
	return &storage.NetworkEntityInfo{
		Type: e.Type,
		Id:   e.ID,
	}
}

// EntityFromProto converts a storage.NetworkEntityInfo proto to an Entity struct.
func EntityFromProto(protoEnt *storage.NetworkEntityInfo) Entity {
	return Entity{
		Type: protoEnt.GetType(),
		ID:   protoEnt.GetId(),
	}
}

// EntityForDeployment returns an Entity struct for the deployment with the given ID.
func EntityForDeployment(id string) Entity {
	return Entity{
		Type: storage.NetworkEntityInfo_DEPLOYMENT,
		ID:   id,
	}
}

// InternetEntity returns the de-facto INTERNET network entity to which all the connections to unidentified external sources are attributed to.
func InternetEntity() Entity {
	return Entity{
		ID:   InternetExternalSourceID,
		Type: storage.NetworkEntityInfo_INTERNET,
	}
}
