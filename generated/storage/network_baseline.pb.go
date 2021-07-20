// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/network_baseline.proto

package storage

import (
	fmt "fmt"
	types "github.com/gogo/protobuf/types"
	proto "github.com/golang/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// NetworkBaselineConnectionProperties represents information about a baseline connection
// next available tag: 4
type NetworkBaselineConnectionProperties struct {
	// Whether this connection is an ingress/egress, from the PoV
	// of the deployment whose baseline this is in
	Ingress bool `protobuf:"varint,1,opt,name=ingress,proto3" json:"ingress,omitempty"`
	// May be 0 if not applicable (e.g., icmp), and denotes the destination port
	Port                 uint32     `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Protocol             L4Protocol `protobuf:"varint,3,opt,name=protocol,proto3,enum=storage.L4Protocol" json:"protocol,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *NetworkBaselineConnectionProperties) Reset()         { *m = NetworkBaselineConnectionProperties{} }
func (m *NetworkBaselineConnectionProperties) String() string { return proto.CompactTextString(m) }
func (*NetworkBaselineConnectionProperties) ProtoMessage()    {}
func (*NetworkBaselineConnectionProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_39bee8d8b4e8019b, []int{0}
}
func (m *NetworkBaselineConnectionProperties) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *NetworkBaselineConnectionProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_NetworkBaselineConnectionProperties.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *NetworkBaselineConnectionProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkBaselineConnectionProperties.Merge(m, src)
}
func (m *NetworkBaselineConnectionProperties) XXX_Size() int {
	return m.Size()
}
func (m *NetworkBaselineConnectionProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkBaselineConnectionProperties.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkBaselineConnectionProperties proto.InternalMessageInfo

func (m *NetworkBaselineConnectionProperties) GetIngress() bool {
	if m != nil {
		return m.Ingress
	}
	return false
}

func (m *NetworkBaselineConnectionProperties) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *NetworkBaselineConnectionProperties) GetProtocol() L4Protocol {
	if m != nil {
		return m.Protocol
	}
	return L4Protocol_L4_PROTOCOL_UNKNOWN
}

func (m *NetworkBaselineConnectionProperties) MessageClone() proto.Message {
	return m.Clone()
}
func (m *NetworkBaselineConnectionProperties) Clone() *NetworkBaselineConnectionProperties {
	if m == nil {
		return nil
	}
	cloned := new(NetworkBaselineConnectionProperties)
	*cloned = *m

	return cloned
}

// NetworkBaselinePeer represents a baseline peer.
// next available tag: 3
type NetworkBaselinePeer struct {
	Entity *NetworkEntity `protobuf:"bytes,1,opt,name=entity,proto3" json:"entity,omitempty"`
	// Will always have at least one element
	Properties           []*NetworkBaselineConnectionProperties `protobuf:"bytes,2,rep,name=properties,proto3" json:"properties,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                               `json:"-"`
	XXX_unrecognized     []byte                                 `json:"-"`
	XXX_sizecache        int32                                  `json:"-"`
}

func (m *NetworkBaselinePeer) Reset()         { *m = NetworkBaselinePeer{} }
func (m *NetworkBaselinePeer) String() string { return proto.CompactTextString(m) }
func (*NetworkBaselinePeer) ProtoMessage()    {}
func (*NetworkBaselinePeer) Descriptor() ([]byte, []int) {
	return fileDescriptor_39bee8d8b4e8019b, []int{1}
}
func (m *NetworkBaselinePeer) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *NetworkBaselinePeer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_NetworkBaselinePeer.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *NetworkBaselinePeer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkBaselinePeer.Merge(m, src)
}
func (m *NetworkBaselinePeer) XXX_Size() int {
	return m.Size()
}
func (m *NetworkBaselinePeer) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkBaselinePeer.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkBaselinePeer proto.InternalMessageInfo

func (m *NetworkBaselinePeer) GetEntity() *NetworkEntity {
	if m != nil {
		return m.Entity
	}
	return nil
}

func (m *NetworkBaselinePeer) GetProperties() []*NetworkBaselineConnectionProperties {
	if m != nil {
		return m.Properties
	}
	return nil
}

func (m *NetworkBaselinePeer) MessageClone() proto.Message {
	return m.Clone()
}
func (m *NetworkBaselinePeer) Clone() *NetworkBaselinePeer {
	if m == nil {
		return nil
	}
	cloned := new(NetworkBaselinePeer)
	*cloned = *m

	cloned.Entity = m.Entity.Clone()
	if m.Properties != nil {
		cloned.Properties = make([]*NetworkBaselineConnectionProperties, len(m.Properties))
		for idx, v := range m.Properties {
			cloned.Properties[idx] = v.Clone()
		}
	}
	return cloned
}

// NetworkBaseline represents a network baseline of a deployment. It contains all
// the baseline peers and their respective connections.
// next available tag: 8
type NetworkBaseline struct {
	// This is the ID of the baseline.
	DeploymentId string                 `protobuf:"bytes,1,opt,name=deployment_id,json=deploymentId,proto3" json:"deployment_id,omitempty"`
	ClusterId    string                 `protobuf:"bytes,2,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	Namespace    string                 `protobuf:"bytes,3,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Peers        []*NetworkBaselinePeer `protobuf:"bytes,4,rep,name=peers,proto3" json:"peers,omitempty"`
	// A list of peers that will never be added to the baseline.
	// For now, this contains peers that the user has manually removed.
	// This is used to ensure we don't add it back in the event
	// we see the flow again.
	ForbiddenPeers       []*NetworkBaselinePeer `protobuf:"bytes,5,rep,name=forbidden_peers,json=forbiddenPeers,proto3" json:"forbidden_peers,omitempty"`
	ObservationPeriodEnd *types.Timestamp       `protobuf:"bytes,6,opt,name=observation_period_end,json=observationPeriodEnd,proto3" json:"observation_period_end,omitempty"`
	// Indicates if this baseline has been locked by user.
	// Here locking means:
	//   1: Do not let system automatically add any allowed peer to baseline
	//   2: Start reporting violations on flows that are not in the baseline
	Locked               bool     `protobuf:"varint,7,opt,name=locked,proto3" json:"locked,omitempty"`
	DeploymentName       string   `protobuf:"bytes,8,opt,name=deployment_name,json=deploymentName,proto3" json:"deployment_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NetworkBaseline) Reset()         { *m = NetworkBaseline{} }
func (m *NetworkBaseline) String() string { return proto.CompactTextString(m) }
func (*NetworkBaseline) ProtoMessage()    {}
func (*NetworkBaseline) Descriptor() ([]byte, []int) {
	return fileDescriptor_39bee8d8b4e8019b, []int{2}
}
func (m *NetworkBaseline) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *NetworkBaseline) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_NetworkBaseline.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *NetworkBaseline) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkBaseline.Merge(m, src)
}
func (m *NetworkBaseline) XXX_Size() int {
	return m.Size()
}
func (m *NetworkBaseline) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkBaseline.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkBaseline proto.InternalMessageInfo

func (m *NetworkBaseline) GetDeploymentId() string {
	if m != nil {
		return m.DeploymentId
	}
	return ""
}

func (m *NetworkBaseline) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *NetworkBaseline) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *NetworkBaseline) GetPeers() []*NetworkBaselinePeer {
	if m != nil {
		return m.Peers
	}
	return nil
}

func (m *NetworkBaseline) GetForbiddenPeers() []*NetworkBaselinePeer {
	if m != nil {
		return m.ForbiddenPeers
	}
	return nil
}

func (m *NetworkBaseline) GetObservationPeriodEnd() *types.Timestamp {
	if m != nil {
		return m.ObservationPeriodEnd
	}
	return nil
}

func (m *NetworkBaseline) GetLocked() bool {
	if m != nil {
		return m.Locked
	}
	return false
}

func (m *NetworkBaseline) GetDeploymentName() string {
	if m != nil {
		return m.DeploymentName
	}
	return ""
}

func (m *NetworkBaseline) MessageClone() proto.Message {
	return m.Clone()
}
func (m *NetworkBaseline) Clone() *NetworkBaseline {
	if m == nil {
		return nil
	}
	cloned := new(NetworkBaseline)
	*cloned = *m

	if m.Peers != nil {
		cloned.Peers = make([]*NetworkBaselinePeer, len(m.Peers))
		for idx, v := range m.Peers {
			cloned.Peers[idx] = v.Clone()
		}
	}
	if m.ForbiddenPeers != nil {
		cloned.ForbiddenPeers = make([]*NetworkBaselinePeer, len(m.ForbiddenPeers))
		for idx, v := range m.ForbiddenPeers {
			cloned.ForbiddenPeers[idx] = v.Clone()
		}
	}
	cloned.ObservationPeriodEnd = m.ObservationPeriodEnd.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*NetworkBaselineConnectionProperties)(nil), "storage.NetworkBaselineConnectionProperties")
	proto.RegisterType((*NetworkBaselinePeer)(nil), "storage.NetworkBaselinePeer")
	proto.RegisterType((*NetworkBaseline)(nil), "storage.NetworkBaseline")
}

func init() { proto.RegisterFile("storage/network_baseline.proto", fileDescriptor_39bee8d8b4e8019b) }

var fileDescriptor_39bee8d8b4e8019b = []byte{
	// 468 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x53, 0x4d, 0x6b, 0xdb, 0x40,
	0x10, 0xad, 0xec, 0xc4, 0x1f, 0x93, 0xc6, 0x86, 0x4d, 0x31, 0xaa, 0x49, 0x5d, 0xe3, 0x1c, 0xea,
	0x43, 0x91, 0xc1, 0xcd, 0x2f, 0x48, 0xf1, 0x21, 0x10, 0x82, 0x10, 0x3d, 0xf5, 0x22, 0x24, 0xed,
	0xd8, 0x2c, 0x96, 0x76, 0x96, 0xdd, 0x4d, 0xd3, 0x1c, 0x0b, 0xfd, 0x07, 0xbd, 0xf4, 0x27, 0xf5,
	0xd8, 0x9f, 0x50, 0xdc, 0x3f, 0x52, 0xbc, 0x92, 0x6c, 0x63, 0x68, 0xe9, 0xcd, 0xfb, 0xe6, 0xbd,
	0xe7, 0x37, 0x8f, 0x11, 0x8c, 0x8c, 0x25, 0x9d, 0xac, 0x70, 0x26, 0xd1, 0x3e, 0x92, 0x5e, 0xc7,
	0x69, 0x62, 0x30, 0x17, 0x12, 0x03, 0xa5, 0xc9, 0x12, 0x6b, 0x57, 0xf3, 0xe1, 0xeb, 0x15, 0xd1,
	0x2a, 0xc7, 0x99, 0x83, 0xd3, 0x87, 0xe5, 0xcc, 0x8a, 0x02, 0x8d, 0x4d, 0x0a, 0x55, 0x32, 0x87,
	0xc3, 0x63, 0xa7, 0x65, 0x4e, 0x8f, 0xe5, 0x6c, 0xf2, 0xd5, 0x83, 0xab, 0xfb, 0x12, 0xbe, 0xa9,
	0xfc, 0xdf, 0x93, 0x94, 0x98, 0x59, 0x41, 0x32, 0xd4, 0xa4, 0x50, 0x5b, 0x81, 0x86, 0xf9, 0xd0,
	0x16, 0x72, 0xa5, 0xd1, 0x18, 0xdf, 0x1b, 0x7b, 0xd3, 0x4e, 0x54, 0x3f, 0x19, 0x83, 0x13, 0x45,
	0xda, 0xfa, 0x8d, 0xb1, 0x37, 0x3d, 0x8f, 0xdc, 0x6f, 0x36, 0x83, 0x8e, 0xb3, 0xcf, 0x28, 0xf7,
	0x9b, 0x63, 0x6f, 0xda, 0x9b, 0x5f, 0x04, 0x55, 0x88, 0xe0, 0xee, 0x3a, 0xac, 0x46, 0xd1, 0x8e,
	0x34, 0xf9, 0xe6, 0xc1, 0xc5, 0x51, 0x8c, 0x10, 0x51, 0xb3, 0x00, 0x5a, 0x28, 0xad, 0xb0, 0x4f,
	0xee, 0x5f, 0xcf, 0xe6, 0x83, 0x9d, 0x4d, 0xc5, 0x5e, 0xb8, 0x69, 0x54, 0xb1, 0xd8, 0x1d, 0x80,
	0xda, 0x85, 0xf6, 0x1b, 0xe3, 0xe6, 0xf4, 0x6c, 0xfe, 0xf6, 0x58, 0xf3, 0xaf, 0x45, 0xa3, 0x03,
	0xfd, 0xe4, 0x4b, 0x13, 0xfa, 0x47, 0x1a, 0x76, 0x05, 0xe7, 0x1c, 0x55, 0x4e, 0x4f, 0x05, 0x4a,
	0x1b, 0x0b, 0xee, 0x82, 0x75, 0xa3, 0xe7, 0x7b, 0xf0, 0x96, 0xb3, 0x57, 0x00, 0x59, 0xfe, 0x60,
	0x2c, 0xea, 0x2d, 0xa3, 0xe1, 0x18, 0xdd, 0x0a, 0xb9, 0xe5, 0xec, 0x12, 0xba, 0x32, 0x29, 0xd0,
	0xa8, 0x24, 0x43, 0xd7, 0x4f, 0x37, 0xda, 0x03, 0x6c, 0x0e, 0xa7, 0x0a, 0x51, 0x1b, 0xff, 0xc4,
	0xc5, 0xbf, 0xfc, 0x5b, 0xfc, 0x6d, 0x41, 0x51, 0x49, 0x65, 0x0b, 0xe8, 0x2f, 0x49, 0xa7, 0x82,
	0x73, 0x94, 0x71, 0xa9, 0x3e, 0xfd, 0x0f, 0x75, 0x6f, 0x27, 0x0a, 0x9d, 0x4d, 0x08, 0x03, 0x4a,
	0x0d, 0xea, 0x4f, 0xc9, 0xb6, 0x95, 0x58, 0xa1, 0x16, 0xc4, 0x63, 0x94, 0xdc, 0x6f, 0xb9, 0xfa,
	0x87, 0x41, 0x79, 0x6b, 0x41, 0x7d, 0x6b, 0xc1, 0x87, 0xfa, 0xd6, 0xa2, 0x17, 0x07, 0xca, 0xd0,
	0x09, 0x17, 0x92, 0xb3, 0x01, 0xb4, 0x72, 0xca, 0xd6, 0xc8, 0xfd, 0xb6, 0x3b, 0x9b, 0xea, 0xc5,
	0xde, 0x40, 0xff, 0xa0, 0xc6, 0xed, 0xf2, 0x7e, 0xc7, 0x15, 0xd1, 0xdb, 0xc3, 0xf7, 0x49, 0x81,
	0x37, 0xd7, 0x3f, 0x36, 0x23, 0xef, 0xe7, 0x66, 0xe4, 0xfd, 0xda, 0x8c, 0xbc, 0xef, 0xbf, 0x47,
	0xcf, 0xe0, 0xa5, 0xa0, 0xc0, 0xd8, 0x24, 0x5b, 0x6b, 0xfa, 0x5c, 0x06, 0xa9, 0x77, 0xfc, 0x58,
	0x7f, 0x13, 0x69, 0xcb, 0xe1, 0xef, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0x42, 0xa2, 0x78, 0x7d,
	0x45, 0x03, 0x00, 0x00,
}

func (m *NetworkBaselineConnectionProperties) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *NetworkBaselineConnectionProperties) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *NetworkBaselineConnectionProperties) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Protocol != 0 {
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(m.Protocol))
		i--
		dAtA[i] = 0x18
	}
	if m.Port != 0 {
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(m.Port))
		i--
		dAtA[i] = 0x10
	}
	if m.Ingress {
		i--
		if m.Ingress {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *NetworkBaselinePeer) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *NetworkBaselinePeer) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *NetworkBaselinePeer) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Properties) > 0 {
		for iNdEx := len(m.Properties) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Properties[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintNetworkBaseline(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Entity != nil {
		{
			size, err := m.Entity.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintNetworkBaseline(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *NetworkBaseline) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *NetworkBaseline) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *NetworkBaseline) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.DeploymentName) > 0 {
		i -= len(m.DeploymentName)
		copy(dAtA[i:], m.DeploymentName)
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(len(m.DeploymentName)))
		i--
		dAtA[i] = 0x42
	}
	if m.Locked {
		i--
		if m.Locked {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x38
	}
	if m.ObservationPeriodEnd != nil {
		{
			size, err := m.ObservationPeriodEnd.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintNetworkBaseline(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	if len(m.ForbiddenPeers) > 0 {
		for iNdEx := len(m.ForbiddenPeers) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.ForbiddenPeers[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintNetworkBaseline(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x2a
		}
	}
	if len(m.Peers) > 0 {
		for iNdEx := len(m.Peers) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Peers[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintNetworkBaseline(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x22
		}
	}
	if len(m.Namespace) > 0 {
		i -= len(m.Namespace)
		copy(dAtA[i:], m.Namespace)
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(len(m.Namespace)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.ClusterId) > 0 {
		i -= len(m.ClusterId)
		copy(dAtA[i:], m.ClusterId)
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(len(m.ClusterId)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.DeploymentId) > 0 {
		i -= len(m.DeploymentId)
		copy(dAtA[i:], m.DeploymentId)
		i = encodeVarintNetworkBaseline(dAtA, i, uint64(len(m.DeploymentId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintNetworkBaseline(dAtA []byte, offset int, v uint64) int {
	offset -= sovNetworkBaseline(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *NetworkBaselineConnectionProperties) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Ingress {
		n += 2
	}
	if m.Port != 0 {
		n += 1 + sovNetworkBaseline(uint64(m.Port))
	}
	if m.Protocol != 0 {
		n += 1 + sovNetworkBaseline(uint64(m.Protocol))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *NetworkBaselinePeer) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Entity != nil {
		l = m.Entity.Size()
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	if len(m.Properties) > 0 {
		for _, e := range m.Properties {
			l = e.Size()
			n += 1 + l + sovNetworkBaseline(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *NetworkBaseline) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.DeploymentId)
	if l > 0 {
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	l = len(m.ClusterId)
	if l > 0 {
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	l = len(m.Namespace)
	if l > 0 {
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	if len(m.Peers) > 0 {
		for _, e := range m.Peers {
			l = e.Size()
			n += 1 + l + sovNetworkBaseline(uint64(l))
		}
	}
	if len(m.ForbiddenPeers) > 0 {
		for _, e := range m.ForbiddenPeers {
			l = e.Size()
			n += 1 + l + sovNetworkBaseline(uint64(l))
		}
	}
	if m.ObservationPeriodEnd != nil {
		l = m.ObservationPeriodEnd.Size()
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	if m.Locked {
		n += 2
	}
	l = len(m.DeploymentName)
	if l > 0 {
		n += 1 + l + sovNetworkBaseline(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovNetworkBaseline(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozNetworkBaseline(x uint64) (n int) {
	return sovNetworkBaseline(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *NetworkBaselineConnectionProperties) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetworkBaseline
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: NetworkBaselineConnectionProperties: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NetworkBaselineConnectionProperties: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ingress", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Ingress = bool(v != 0)
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Port", wireType)
			}
			m.Port = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Port |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Protocol", wireType)
			}
			m.Protocol = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Protocol |= L4Protocol(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipNetworkBaseline(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *NetworkBaselinePeer) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetworkBaseline
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: NetworkBaselinePeer: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NetworkBaselinePeer: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Entity", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Entity == nil {
				m.Entity = &NetworkEntity{}
			}
			if err := m.Entity.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Properties", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Properties = append(m.Properties, &NetworkBaselineConnectionProperties{})
			if err := m.Properties[len(m.Properties)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetworkBaseline(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *NetworkBaseline) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetworkBaseline
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: NetworkBaseline: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NetworkBaseline: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DeploymentId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DeploymentId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Namespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Namespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Peers", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Peers = append(m.Peers, &NetworkBaselinePeer{})
			if err := m.Peers[len(m.Peers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ForbiddenPeers", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ForbiddenPeers = append(m.ForbiddenPeers, &NetworkBaselinePeer{})
			if err := m.ForbiddenPeers[len(m.ForbiddenPeers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObservationPeriodEnd", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ObservationPeriodEnd == nil {
				m.ObservationPeriodEnd = &types.Timestamp{}
			}
			if err := m.ObservationPeriodEnd.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Locked", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Locked = bool(v != 0)
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DeploymentName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DeploymentName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetworkBaseline(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetworkBaseline
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipNetworkBaseline(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowNetworkBaseline
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowNetworkBaseline
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthNetworkBaseline
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupNetworkBaseline
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthNetworkBaseline
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthNetworkBaseline        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowNetworkBaseline          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupNetworkBaseline = fmt.Errorf("proto: unexpected end of group")
)
