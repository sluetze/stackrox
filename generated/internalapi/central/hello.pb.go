// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: internalapi/central/hello.proto

package central

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	storage "github.com/stackrox/rox/generated/storage"
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

type HelmManagedConfigInit struct {
	ClusterConfig        *storage.CompleteClusterConfig `protobuf:"bytes,1,opt,name=cluster_config,json=clusterConfig,proto3" json:"cluster_config,omitempty"`
	ClusterName          string                         `protobuf:"bytes,2,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
	ClusterId            string                         `protobuf:"bytes,3,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	NotHelmManaged       bool                           `protobuf:"varint,4,opt,name=not_helm_managed,json=notHelmManaged,proto3" json:"not_helm_managed,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                       `json:"-"`
	XXX_unrecognized     []byte                         `json:"-"`
	XXX_sizecache        int32                          `json:"-"`
}

func (m *HelmManagedConfigInit) Reset()         { *m = HelmManagedConfigInit{} }
func (m *HelmManagedConfigInit) String() string { return proto.CompactTextString(m) }
func (*HelmManagedConfigInit) ProtoMessage()    {}
func (*HelmManagedConfigInit) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce25d1bd48ec88b4, []int{0}
}
func (m *HelmManagedConfigInit) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *HelmManagedConfigInit) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_HelmManagedConfigInit.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *HelmManagedConfigInit) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HelmManagedConfigInit.Merge(m, src)
}
func (m *HelmManagedConfigInit) XXX_Size() int {
	return m.Size()
}
func (m *HelmManagedConfigInit) XXX_DiscardUnknown() {
	xxx_messageInfo_HelmManagedConfigInit.DiscardUnknown(m)
}

var xxx_messageInfo_HelmManagedConfigInit proto.InternalMessageInfo

func (m *HelmManagedConfigInit) GetClusterConfig() *storage.CompleteClusterConfig {
	if m != nil {
		return m.ClusterConfig
	}
	return nil
}

func (m *HelmManagedConfigInit) GetClusterName() string {
	if m != nil {
		return m.ClusterName
	}
	return ""
}

func (m *HelmManagedConfigInit) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *HelmManagedConfigInit) GetNotHelmManaged() bool {
	if m != nil {
		return m.NotHelmManaged
	}
	return false
}

func (m *HelmManagedConfigInit) MessageClone() proto.Message {
	return m.Clone()
}
func (m *HelmManagedConfigInit) Clone() *HelmManagedConfigInit {
	if m == nil {
		return nil
	}
	cloned := new(HelmManagedConfigInit)
	*cloned = *m

	cloned.ClusterConfig = m.ClusterConfig.Clone()
	return cloned
}

type SensorHello struct {
	SensorVersion            string                                  `protobuf:"bytes,1,opt,name=sensor_version,json=sensorVersion,proto3" json:"sensor_version,omitempty"`
	Capabilities             []string                                `protobuf:"bytes,2,rep,name=capabilities,proto3" json:"capabilities,omitempty"`
	DeploymentIdentification *storage.SensorDeploymentIdentification `protobuf:"bytes,5,opt,name=deployment_identification,json=deploymentIdentification,proto3" json:"deployment_identification,omitempty"`
	HelmManagedConfigInit    *HelmManagedConfigInit                  `protobuf:"bytes,3,opt,name=helm_managed_config_init,json=helmManagedConfigInit,proto3" json:"helm_managed_config_init,omitempty"`
	// Policy version sensor understands. If unset, central will try to guess it.
	PolicyVersion        string   `protobuf:"bytes,4,opt,name=policy_version,json=policyVersion,proto3" json:"policy_version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SensorHello) Reset()         { *m = SensorHello{} }
func (m *SensorHello) String() string { return proto.CompactTextString(m) }
func (*SensorHello) ProtoMessage()    {}
func (*SensorHello) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce25d1bd48ec88b4, []int{1}
}
func (m *SensorHello) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SensorHello) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SensorHello.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SensorHello) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SensorHello.Merge(m, src)
}
func (m *SensorHello) XXX_Size() int {
	return m.Size()
}
func (m *SensorHello) XXX_DiscardUnknown() {
	xxx_messageInfo_SensorHello.DiscardUnknown(m)
}

var xxx_messageInfo_SensorHello proto.InternalMessageInfo

func (m *SensorHello) GetSensorVersion() string {
	if m != nil {
		return m.SensorVersion
	}
	return ""
}

func (m *SensorHello) GetCapabilities() []string {
	if m != nil {
		return m.Capabilities
	}
	return nil
}

func (m *SensorHello) GetDeploymentIdentification() *storage.SensorDeploymentIdentification {
	if m != nil {
		return m.DeploymentIdentification
	}
	return nil
}

func (m *SensorHello) GetHelmManagedConfigInit() *HelmManagedConfigInit {
	if m != nil {
		return m.HelmManagedConfigInit
	}
	return nil
}

func (m *SensorHello) GetPolicyVersion() string {
	if m != nil {
		return m.PolicyVersion
	}
	return ""
}

func (m *SensorHello) MessageClone() proto.Message {
	return m.Clone()
}
func (m *SensorHello) Clone() *SensorHello {
	if m == nil {
		return nil
	}
	cloned := new(SensorHello)
	*cloned = *m

	if m.Capabilities != nil {
		cloned.Capabilities = make([]string, len(m.Capabilities))
		copy(cloned.Capabilities, m.Capabilities)
	}
	cloned.DeploymentIdentification = m.DeploymentIdentification.Clone()
	cloned.HelmManagedConfigInit = m.HelmManagedConfigInit.Clone()
	return cloned
}

type CentralHello struct {
	ClusterId            string            `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	CertBundle           map[string]string `protobuf:"bytes,2,rep,name=cert_bundle,json=certBundle,proto3" json:"cert_bundle,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *CentralHello) Reset()         { *m = CentralHello{} }
func (m *CentralHello) String() string { return proto.CompactTextString(m) }
func (*CentralHello) ProtoMessage()    {}
func (*CentralHello) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce25d1bd48ec88b4, []int{2}
}
func (m *CentralHello) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CentralHello) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CentralHello.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CentralHello) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CentralHello.Merge(m, src)
}
func (m *CentralHello) XXX_Size() int {
	return m.Size()
}
func (m *CentralHello) XXX_DiscardUnknown() {
	xxx_messageInfo_CentralHello.DiscardUnknown(m)
}

var xxx_messageInfo_CentralHello proto.InternalMessageInfo

func (m *CentralHello) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *CentralHello) GetCertBundle() map[string]string {
	if m != nil {
		return m.CertBundle
	}
	return nil
}

func (m *CentralHello) MessageClone() proto.Message {
	return m.Clone()
}
func (m *CentralHello) Clone() *CentralHello {
	if m == nil {
		return nil
	}
	cloned := new(CentralHello)
	*cloned = *m

	if m.CertBundle != nil {
		cloned.CertBundle = make(map[string]string, len(m.CertBundle))
		for k, v := range m.CertBundle {
			cloned.CertBundle[k] = v
		}
	}
	return cloned
}

func init() {
	proto.RegisterType((*HelmManagedConfigInit)(nil), "central.HelmManagedConfigInit")
	proto.RegisterType((*SensorHello)(nil), "central.SensorHello")
	proto.RegisterType((*CentralHello)(nil), "central.CentralHello")
	proto.RegisterMapType((map[string]string)(nil), "central.CentralHello.CertBundleEntry")
}

func init() { proto.RegisterFile("internalapi/central/hello.proto", fileDescriptor_ce25d1bd48ec88b4) }

var fileDescriptor_ce25d1bd48ec88b4 = []byte{
	// 465 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x92, 0xc1, 0x8a, 0x13, 0x4f,
	0x10, 0xc6, 0xff, 0x9d, 0xec, 0xfe, 0x35, 0x35, 0xd9, 0xb8, 0x34, 0x06, 0x66, 0x17, 0x1c, 0x63,
	0x20, 0x38, 0xa7, 0x09, 0xac, 0x17, 0x11, 0xbc, 0xec, 0xb8, 0xb2, 0x39, 0xe8, 0x61, 0x04, 0x05,
	0x2f, 0x43, 0x67, 0xa6, 0x36, 0x69, 0xec, 0xe9, 0x1e, 0x7a, 0x3a, 0x0b, 0x79, 0x13, 0x1f, 0xc4,
	0xb3, 0x67, 0xf1, 0xe4, 0x23, 0x48, 0x7c, 0x11, 0x49, 0x77, 0x67, 0x48, 0x96, 0xf5, 0x96, 0xfa,
	0xea, 0x4b, 0x4d, 0xf5, 0xef, 0x2b, 0x78, 0xca, 0xa5, 0x41, 0x2d, 0x99, 0x60, 0x35, 0x9f, 0x16,
	0x28, 0x8d, 0x66, 0x62, 0xba, 0x44, 0x21, 0x54, 0x52, 0x6b, 0x65, 0x14, 0x7d, 0xe0, 0xc5, 0xf3,
	0x61, 0x63, 0x94, 0x66, 0x0b, 0x9c, 0x16, 0x62, 0xd5, 0x18, 0xd4, 0xae, 0x3f, 0xfe, 0x49, 0x60,
	0x78, 0x8d, 0xa2, 0x7a, 0xc7, 0x24, 0x5b, 0x60, 0x99, 0x2a, 0x79, 0xc3, 0x17, 0x33, 0xc9, 0x0d,
	0xbd, 0x82, 0x81, 0xb7, 0xe6, 0x85, 0x55, 0x43, 0x32, 0x22, 0x71, 0x70, 0x11, 0x25, 0x7e, 0x52,
	0x92, 0xaa, 0xaa, 0x16, 0x68, 0x30, 0x75, 0x36, 0xf7, 0xdf, 0xec, 0xa4, 0xd8, 0x2f, 0xe9, 0x33,
	0xe8, 0xef, 0xc6, 0x48, 0x56, 0x61, 0xd8, 0x19, 0x91, 0xb8, 0x97, 0x05, 0x5e, 0x7b, 0xcf, 0x2a,
	0xa4, 0x4f, 0x00, 0x76, 0x16, 0x5e, 0x86, 0x5d, 0x6b, 0xe8, 0x79, 0x65, 0x56, 0xd2, 0x18, 0x4e,
	0xa5, 0x32, 0xf9, 0x12, 0x45, 0x95, 0x57, 0x6e, 0xcd, 0xf0, 0x68, 0x44, 0xe2, 0x87, 0xd9, 0x40,
	0x2a, 0xb3, 0xb7, 0xfc, 0xf8, 0x7b, 0x07, 0x82, 0x0f, 0x28, 0x1b, 0xa5, 0xaf, 0xb7, 0x08, 0xe8,
	0x04, 0x06, 0x8d, 0x2d, 0xf3, 0x5b, 0xd4, 0x0d, 0x57, 0xd2, 0x3e, 0xa1, 0x97, 0x9d, 0x38, 0xf5,
	0xa3, 0x13, 0xe9, 0x18, 0xfa, 0x05, 0xab, 0xd9, 0x9c, 0x0b, 0x6e, 0x38, 0x36, 0x61, 0x67, 0xd4,
	0x8d, 0x7b, 0xd9, 0x81, 0x46, 0x4b, 0x38, 0x2b, 0xb1, 0x16, 0x6a, 0x5d, 0xa1, 0x34, 0x39, 0x2f,
	0x51, 0x1a, 0x7e, 0xc3, 0x0b, 0x66, 0xb6, 0x53, 0x8f, 0x2d, 0x98, 0xe7, 0x2d, 0x18, 0xb7, 0xc3,
	0x9b, 0xd6, 0x3f, 0x3b, 0xb0, 0x67, 0x61, 0xf9, 0x8f, 0x0e, 0xfd, 0x04, 0xe1, 0xfe, 0x33, 0x3d,
	0xf8, 0x9c, 0x4b, 0x6e, 0x2c, 0x97, 0x2d, 0x7d, 0x1f, 0x68, 0x72, 0x6f, 0x6a, 0xd9, 0x70, 0x79,
	0x6f, 0x98, 0x13, 0x18, 0xd4, 0x4a, 0xf0, 0x62, 0xdd, 0x92, 0x38, 0x72, 0x24, 0x9c, 0xea, 0x49,
	0x8c, 0xbf, 0x11, 0xe8, 0xa7, 0x6e, 0xbe, 0x23, 0x78, 0x18, 0x0d, 0xb9, 0x1b, 0xcd, 0x5b, 0x08,
	0x0a, 0xd4, 0x26, 0x9f, 0xaf, 0x64, 0x29, 0xd0, 0x82, 0x0b, 0x2e, 0x26, 0xed, 0x8a, 0xfb, 0xa3,
	0x92, 0x14, 0xb5, 0xb9, 0xb4, 0xbe, 0x2b, 0x69, 0xf4, 0x3a, 0x83, 0xa2, 0x15, 0xce, 0x5f, 0xc3,
	0xa3, 0x3b, 0x6d, 0x7a, 0x0a, 0xdd, 0x2f, 0xb8, 0xf6, 0x9f, 0xdc, 0xfe, 0xa4, 0x8f, 0xe1, 0xf8,
	0x96, 0x89, 0xd5, 0xee, 0x84, 0x5c, 0xf1, 0xaa, 0xf3, 0x92, 0x5c, 0x9e, 0xfd, 0xd8, 0x44, 0xe4,
	0xd7, 0x26, 0x22, 0xbf, 0x37, 0x11, 0xf9, 0xfa, 0x27, 0xfa, 0xef, 0xf3, 0xee, 0xec, 0xe7, 0xff,
	0xdb, 0x33, 0x7f, 0xf1, 0x37, 0x00, 0x00, 0xff, 0xff, 0x3f, 0xe9, 0x3e, 0xb1, 0x29, 0x03, 0x00,
	0x00,
}

func (m *HelmManagedConfigInit) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *HelmManagedConfigInit) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *HelmManagedConfigInit) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.NotHelmManaged {
		i--
		if m.NotHelmManaged {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x20
	}
	if len(m.ClusterId) > 0 {
		i -= len(m.ClusterId)
		copy(dAtA[i:], m.ClusterId)
		i = encodeVarintHello(dAtA, i, uint64(len(m.ClusterId)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.ClusterName) > 0 {
		i -= len(m.ClusterName)
		copy(dAtA[i:], m.ClusterName)
		i = encodeVarintHello(dAtA, i, uint64(len(m.ClusterName)))
		i--
		dAtA[i] = 0x12
	}
	if m.ClusterConfig != nil {
		{
			size, err := m.ClusterConfig.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintHello(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *SensorHello) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SensorHello) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SensorHello) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.DeploymentIdentification != nil {
		{
			size, err := m.DeploymentIdentification.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintHello(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if len(m.PolicyVersion) > 0 {
		i -= len(m.PolicyVersion)
		copy(dAtA[i:], m.PolicyVersion)
		i = encodeVarintHello(dAtA, i, uint64(len(m.PolicyVersion)))
		i--
		dAtA[i] = 0x22
	}
	if m.HelmManagedConfigInit != nil {
		{
			size, err := m.HelmManagedConfigInit.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintHello(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Capabilities) > 0 {
		for iNdEx := len(m.Capabilities) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Capabilities[iNdEx])
			copy(dAtA[i:], m.Capabilities[iNdEx])
			i = encodeVarintHello(dAtA, i, uint64(len(m.Capabilities[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.SensorVersion) > 0 {
		i -= len(m.SensorVersion)
		copy(dAtA[i:], m.SensorVersion)
		i = encodeVarintHello(dAtA, i, uint64(len(m.SensorVersion)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CentralHello) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CentralHello) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CentralHello) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.CertBundle) > 0 {
		for k := range m.CertBundle {
			v := m.CertBundle[k]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = encodeVarintHello(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = encodeVarintHello(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = encodeVarintHello(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.ClusterId) > 0 {
		i -= len(m.ClusterId)
		copy(dAtA[i:], m.ClusterId)
		i = encodeVarintHello(dAtA, i, uint64(len(m.ClusterId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintHello(dAtA []byte, offset int, v uint64) int {
	offset -= sovHello(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *HelmManagedConfigInit) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ClusterConfig != nil {
		l = m.ClusterConfig.Size()
		n += 1 + l + sovHello(uint64(l))
	}
	l = len(m.ClusterName)
	if l > 0 {
		n += 1 + l + sovHello(uint64(l))
	}
	l = len(m.ClusterId)
	if l > 0 {
		n += 1 + l + sovHello(uint64(l))
	}
	if m.NotHelmManaged {
		n += 2
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *SensorHello) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.SensorVersion)
	if l > 0 {
		n += 1 + l + sovHello(uint64(l))
	}
	if len(m.Capabilities) > 0 {
		for _, s := range m.Capabilities {
			l = len(s)
			n += 1 + l + sovHello(uint64(l))
		}
	}
	if m.HelmManagedConfigInit != nil {
		l = m.HelmManagedConfigInit.Size()
		n += 1 + l + sovHello(uint64(l))
	}
	l = len(m.PolicyVersion)
	if l > 0 {
		n += 1 + l + sovHello(uint64(l))
	}
	if m.DeploymentIdentification != nil {
		l = m.DeploymentIdentification.Size()
		n += 1 + l + sovHello(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CentralHello) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ClusterId)
	if l > 0 {
		n += 1 + l + sovHello(uint64(l))
	}
	if len(m.CertBundle) > 0 {
		for k, v := range m.CertBundle {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovHello(uint64(len(k))) + 1 + len(v) + sovHello(uint64(len(v)))
			n += mapEntrySize + 1 + sovHello(uint64(mapEntrySize))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovHello(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozHello(x uint64) (n int) {
	return sovHello(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *HelmManagedConfigInit) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowHello
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
			return fmt.Errorf("proto: HelmManagedConfigInit: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HelmManagedConfigInit: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ClusterConfig == nil {
				m.ClusterConfig = &storage.CompleteClusterConfig{}
			}
			if err := m.ClusterConfig.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NotHelmManaged", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
			m.NotHelmManaged = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipHello(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthHello
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
func (m *SensorHello) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowHello
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
			return fmt.Errorf("proto: SensorHello: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SensorHello: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SensorVersion", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SensorVersion = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Capabilities", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Capabilities = append(m.Capabilities, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HelmManagedConfigInit", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.HelmManagedConfigInit == nil {
				m.HelmManagedConfigInit = &HelmManagedConfigInit{}
			}
			if err := m.HelmManagedConfigInit.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PolicyVersion", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PolicyVersion = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DeploymentIdentification", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DeploymentIdentification == nil {
				m.DeploymentIdentification = &storage.SensorDeploymentIdentification{}
			}
			if err := m.DeploymentIdentification.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipHello(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthHello
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
func (m *CentralHello) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowHello
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
			return fmt.Errorf("proto: CentralHello: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CentralHello: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CertBundle", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowHello
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
				return ErrInvalidLengthHello
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthHello
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CertBundle == nil {
				m.CertBundle = make(map[string]string)
			}
			var mapkey string
			var mapvalue string
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowHello
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
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowHello
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthHello
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthHello
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var stringLenmapvalue uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowHello
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapvalue |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapvalue := int(stringLenmapvalue)
					if intStringLenmapvalue < 0 {
						return ErrInvalidLengthHello
					}
					postStringIndexmapvalue := iNdEx + intStringLenmapvalue
					if postStringIndexmapvalue < 0 {
						return ErrInvalidLengthHello
					}
					if postStringIndexmapvalue > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = string(dAtA[iNdEx:postStringIndexmapvalue])
					iNdEx = postStringIndexmapvalue
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipHello(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if (skippy < 0) || (iNdEx+skippy) < 0 {
						return ErrInvalidLengthHello
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.CertBundle[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipHello(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthHello
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
func skipHello(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowHello
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
					return 0, ErrIntOverflowHello
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
					return 0, ErrIntOverflowHello
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
				return 0, ErrInvalidLengthHello
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupHello
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthHello
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthHello        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowHello          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupHello = fmt.Errorf("proto: unexpected end of group")
)
