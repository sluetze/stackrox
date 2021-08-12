// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/log_integration.proto

package storage

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
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

type LogIntegration struct {
	Id   string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// Denotes the time when the log integration was created.
	CreatedAt *types.Timestamp `protobuf:"bytes,3,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	// Denotes the frequency of log collection. If not supplied, default polling interval shall be applied.
	PollingInterval *types.Duration `protobuf:"bytes,4,opt,name=polling_interval,json=pollingInterval,proto3" json:"polling_interval,omitempty"`
	// Types that are valid to be assigned to Config:
	//	*LogIntegration_EksConfig
	//	*LogIntegration_GkeConfig
	Config               isLogIntegration_Config `protobuf_oneof:"Config"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *LogIntegration) Reset()         { *m = LogIntegration{} }
func (m *LogIntegration) String() string { return proto.CompactTextString(m) }
func (*LogIntegration) ProtoMessage()    {}
func (*LogIntegration) Descriptor() ([]byte, []int) {
	return fileDescriptor_8f9ed249f9d7d834, []int{0}
}
func (m *LogIntegration) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LogIntegration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LogIntegration.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *LogIntegration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogIntegration.Merge(m, src)
}
func (m *LogIntegration) XXX_Size() int {
	return m.Size()
}
func (m *LogIntegration) XXX_DiscardUnknown() {
	xxx_messageInfo_LogIntegration.DiscardUnknown(m)
}

var xxx_messageInfo_LogIntegration proto.InternalMessageInfo

type isLogIntegration_Config interface {
	isLogIntegration_Config()
	MarshalTo([]byte) (int, error)
	Size() int
	Clone() isLogIntegration_Config
}

type LogIntegration_EksConfig struct {
	EksConfig *LogIntegration_AWSConfig `protobuf:"bytes,5,opt,name=eks_config,json=eksConfig,proto3,oneof" json:"eks_config,omitempty"`
}
type LogIntegration_GkeConfig struct {
	GkeConfig *LogIntegration_GCPConfig `protobuf:"bytes,6,opt,name=gke_config,json=gkeConfig,proto3,oneof" json:"gke_config,omitempty"`
}

func (*LogIntegration_EksConfig) isLogIntegration_Config() {}
func (m *LogIntegration_EksConfig) Clone() isLogIntegration_Config {
	if m == nil {
		return nil
	}
	cloned := new(LogIntegration_EksConfig)
	*cloned = *m

	cloned.EksConfig = m.EksConfig.Clone()
	return cloned
}
func (*LogIntegration_GkeConfig) isLogIntegration_Config() {}
func (m *LogIntegration_GkeConfig) Clone() isLogIntegration_Config {
	if m == nil {
		return nil
	}
	cloned := new(LogIntegration_GkeConfig)
	*cloned = *m

	cloned.GkeConfig = m.GkeConfig.Clone()
	return cloned
}

func (m *LogIntegration) GetConfig() isLogIntegration_Config {
	if m != nil {
		return m.Config
	}
	return nil
}

func (m *LogIntegration) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *LogIntegration) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LogIntegration) GetCreatedAt() *types.Timestamp {
	if m != nil {
		return m.CreatedAt
	}
	return nil
}

func (m *LogIntegration) GetPollingInterval() *types.Duration {
	if m != nil {
		return m.PollingInterval
	}
	return nil
}

func (m *LogIntegration) GetEksConfig() *LogIntegration_AWSConfig {
	if x, ok := m.GetConfig().(*LogIntegration_EksConfig); ok {
		return x.EksConfig
	}
	return nil
}

func (m *LogIntegration) GetGkeConfig() *LogIntegration_GCPConfig {
	if x, ok := m.GetConfig().(*LogIntegration_GkeConfig); ok {
		return x.GkeConfig
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*LogIntegration) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*LogIntegration_EksConfig)(nil),
		(*LogIntegration_GkeConfig)(nil),
	}
}

func (m *LogIntegration) MessageClone() proto.Message {
	return m.Clone()
}
func (m *LogIntegration) Clone() *LogIntegration {
	if m == nil {
		return nil
	}
	cloned := new(LogIntegration)
	*cloned = *m

	cloned.CreatedAt = m.CreatedAt.Clone()
	cloned.PollingInterval = m.PollingInterval.Clone()
	if m.Config != nil {
		cloned.Config = m.Config.Clone()
	}
	return cloned
}

type LogIntegration_AWSConfig struct {
	UseIam bool `protobuf:"varint,1,opt,name=use_iam,json=useIam,proto3" json:"use_iam,omitempty" scrub:"dependent"`
	// The access key ID for the storage integration. Cannot use if IAM is selected. The server will mask the value of this credential in responses and logs.
	AccessKeyId string `protobuf:"bytes,2,opt,name=access_key_id,json=accessKeyId,proto3" json:"access_key_id,omitempty" scrub:"always"`
	// The secret access key for the storage integration. Cannot use if IAM is selected. The server will mask the value of this credential in responses and logs.
	SecretAccessKey      string   `protobuf:"bytes,3,opt,name=secret_access_key,json=secretAccessKey,proto3" json:"secret_access_key,omitempty" scrub:"always"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LogIntegration_AWSConfig) Reset()         { *m = LogIntegration_AWSConfig{} }
func (m *LogIntegration_AWSConfig) String() string { return proto.CompactTextString(m) }
func (*LogIntegration_AWSConfig) ProtoMessage()    {}
func (*LogIntegration_AWSConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_8f9ed249f9d7d834, []int{0, 0}
}
func (m *LogIntegration_AWSConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LogIntegration_AWSConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LogIntegration_AWSConfig.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *LogIntegration_AWSConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogIntegration_AWSConfig.Merge(m, src)
}
func (m *LogIntegration_AWSConfig) XXX_Size() int {
	return m.Size()
}
func (m *LogIntegration_AWSConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LogIntegration_AWSConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LogIntegration_AWSConfig proto.InternalMessageInfo

func (m *LogIntegration_AWSConfig) GetUseIam() bool {
	if m != nil {
		return m.UseIam
	}
	return false
}

func (m *LogIntegration_AWSConfig) GetAccessKeyId() string {
	if m != nil {
		return m.AccessKeyId
	}
	return ""
}

func (m *LogIntegration_AWSConfig) GetSecretAccessKey() string {
	if m != nil {
		return m.SecretAccessKey
	}
	return ""
}

func (m *LogIntegration_AWSConfig) MessageClone() proto.Message {
	return m.Clone()
}
func (m *LogIntegration_AWSConfig) Clone() *LogIntegration_AWSConfig {
	if m == nil {
		return nil
	}
	cloned := new(LogIntegration_AWSConfig)
	*cloned = *m

	return cloned
}

type LogIntegration_GCPConfig struct {
	// The service account for the storage integration. If entered, the project id in the JSON has to match the project id provided previously. Cannot use if Workload is selected. The server will mask the value of this credential in responses and logs.
	ServiceAccount       string   `protobuf:"bytes,1,opt,name=service_account,json=serviceAccount,proto3" json:"service_account,omitempty" scrub:"always"`
	UseWorkloadId        bool     `protobuf:"varint,2,opt,name=use_workload_id,json=useWorkloadId,proto3" json:"use_workload_id,omitempty" scrub:"dependent"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LogIntegration_GCPConfig) Reset()         { *m = LogIntegration_GCPConfig{} }
func (m *LogIntegration_GCPConfig) String() string { return proto.CompactTextString(m) }
func (*LogIntegration_GCPConfig) ProtoMessage()    {}
func (*LogIntegration_GCPConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_8f9ed249f9d7d834, []int{0, 1}
}
func (m *LogIntegration_GCPConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LogIntegration_GCPConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LogIntegration_GCPConfig.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *LogIntegration_GCPConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogIntegration_GCPConfig.Merge(m, src)
}
func (m *LogIntegration_GCPConfig) XXX_Size() int {
	return m.Size()
}
func (m *LogIntegration_GCPConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LogIntegration_GCPConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LogIntegration_GCPConfig proto.InternalMessageInfo

func (m *LogIntegration_GCPConfig) GetServiceAccount() string {
	if m != nil {
		return m.ServiceAccount
	}
	return ""
}

func (m *LogIntegration_GCPConfig) GetUseWorkloadId() bool {
	if m != nil {
		return m.UseWorkloadId
	}
	return false
}

func (m *LogIntegration_GCPConfig) MessageClone() proto.Message {
	return m.Clone()
}
func (m *LogIntegration_GCPConfig) Clone() *LogIntegration_GCPConfig {
	if m == nil {
		return nil
	}
	cloned := new(LogIntegration_GCPConfig)
	*cloned = *m

	return cloned
}

func init() {
	proto.RegisterType((*LogIntegration)(nil), "storage.LogIntegration")
	proto.RegisterType((*LogIntegration_AWSConfig)(nil), "storage.LogIntegration.AWSConfig")
	proto.RegisterType((*LogIntegration_GCPConfig)(nil), "storage.LogIntegration.GCPConfig")
}

func init() { proto.RegisterFile("storage/log_integration.proto", fileDescriptor_8f9ed249f9d7d834) }

var fileDescriptor_8f9ed249f9d7d834 = []byte{
	// 487 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x93, 0xdd, 0x6a, 0xd4, 0x4e,
	0x18, 0xc6, 0x9b, 0xfd, 0xb7, 0xdb, 0x66, 0x4a, 0x77, 0xff, 0x1d, 0x14, 0xd2, 0x80, 0xd9, 0xba,
	0x47, 0x3d, 0xca, 0x82, 0x8a, 0xa0, 0xa2, 0xb0, 0x69, 0x41, 0x83, 0x1e, 0x48, 0x14, 0x0a, 0x9e,
	0x84, 0xd9, 0xcc, 0xdb, 0x61, 0xc8, 0xc7, 0x2c, 0x33, 0x93, 0xd6, 0xbd, 0x82, 0xde, 0x82, 0xf7,
	0xe1, 0x4d, 0x78, 0xe8, 0x15, 0x14, 0x59, 0xef, 0xa0, 0x57, 0x20, 0x3b, 0x33, 0xe9, 0xfa, 0x51,
	0x3d, 0x9b, 0x8f, 0xe7, 0xf9, 0xcd, 0xfb, 0xbc, 0x6f, 0x82, 0xee, 0x29, 0x2d, 0x24, 0x61, 0x30,
	0xa9, 0x04, 0xcb, 0x79, 0xa3, 0x81, 0x49, 0xa2, 0xb9, 0x68, 0xe2, 0xb9, 0x14, 0x5a, 0xe0, 0x6d,
	0x77, 0x1d, 0xde, 0x61, 0x82, 0x09, 0x73, 0x36, 0x59, 0xad, 0xec, 0x75, 0x38, 0x62, 0x42, 0xb0,
	0x0a, 0x26, 0x66, 0x37, 0x6b, 0xcf, 0x26, 0x9a, 0xd7, 0xa0, 0x34, 0xa9, 0xe7, 0x4e, 0x10, 0xfd,
	0x2e, 0xa0, 0xed, 0xcf, 0xfc, 0xf1, 0xe5, 0x16, 0x1a, 0xbc, 0x11, 0x2c, 0x5d, 0x3f, 0x8c, 0x07,
	0xa8, 0xc7, 0x69, 0xe0, 0x1d, 0x7a, 0x47, 0x7e, 0xd6, 0xe3, 0x14, 0x63, 0xb4, 0xd9, 0x90, 0x1a,
	0x82, 0x9e, 0x39, 0x31, 0x6b, 0xfc, 0x04, 0xa1, 0x42, 0x02, 0xd1, 0x40, 0x73, 0xa2, 0x83, 0xff,
	0x0e, 0xbd, 0xa3, 0xdd, 0x07, 0x61, 0x6c, 0xdf, 0x8a, 0xbb, 0xb7, 0xe2, 0xf7, 0x5d, 0x31, 0x99,
	0xef, 0xd4, 0x53, 0x8d, 0x4f, 0xd0, 0xff, 0x73, 0x51, 0x55, 0xbc, 0xb1, 0x71, 0xe5, 0x39, 0xa9,
	0x82, 0x4d, 0x03, 0x38, 0xf8, 0x03, 0x70, 0xe2, 0x8a, 0xcd, 0x86, 0xce, 0x92, 0x3a, 0x07, 0x4e,
	0x10, 0x82, 0x52, 0xe5, 0x85, 0x68, 0xce, 0x38, 0x0b, 0xb6, 0x8c, 0xff, 0x7e, 0xec, 0x9a, 0x15,
	0xff, 0x9a, 0x28, 0x9e, 0x9e, 0xbe, 0x3b, 0x36, 0xc2, 0x57, 0x1b, 0x99, 0x0f, 0xa5, 0xb2, 0x9b,
	0x15, 0x83, 0x95, 0xd0, 0x31, 0xfa, 0xff, 0x66, 0xbc, 0x3c, 0x7e, 0xbb, 0x66, 0xb0, 0x12, 0xec,
	0x26, 0xfc, 0xec, 0x21, 0xff, 0x06, 0x8f, 0x63, 0xb4, 0xdd, 0x2a, 0xc8, 0x39, 0xa9, 0x4d, 0xff,
	0x76, 0x92, 0xbb, 0xd7, 0x57, 0xa3, 0x7d, 0x55, 0xc8, 0x76, 0xf6, 0x74, 0x4c, 0x61, 0x0e, 0x0d,
	0x85, 0x46, 0x8f, 0xb3, 0x7e, 0xab, 0x20, 0x25, 0x35, 0x7e, 0x8c, 0xf6, 0x48, 0x51, 0x80, 0x52,
	0x79, 0x09, 0x8b, 0x9c, 0x53, 0xdb, 0xe3, 0x04, 0x5f, 0x5f, 0x8d, 0x06, 0xce, 0x45, 0xaa, 0x0b,
	0xb2, 0x50, 0xe3, 0x6c, 0xd7, 0x0a, 0x5f, 0xc3, 0x22, 0xa5, 0xf8, 0x05, 0xda, 0x57, 0x50, 0x48,
	0xd0, 0xf9, 0xda, 0x6e, 0xa6, 0x70, 0xbb, 0x77, 0x68, 0xc5, 0xd3, 0x8e, 0x10, 0x5e, 0x7a, 0xc8,
	0xbf, 0x09, 0x84, 0x9f, 0xa1, 0xa1, 0x02, 0x79, 0xce, 0x0b, 0x58, 0xe1, 0x44, 0xdb, 0x68, 0x3b,
	0xfd, 0x5b, 0x59, 0x03, 0x27, 0x9d, 0x5a, 0x25, 0x7e, 0x8e, 0x86, 0xab, 0xc8, 0x17, 0x42, 0x96,
	0x95, 0x20, 0xb4, 0x0b, 0xf1, 0xd7, 0xe8, 0x7b, 0xad, 0x82, 0x53, 0x27, 0x4e, 0x69, 0xb2, 0x83,
	0xfa, 0xb6, 0x8a, 0xe4, 0xd1, 0x97, 0x65, 0xe4, 0x7d, 0x5d, 0x46, 0xde, 0xb7, 0x65, 0xe4, 0x7d,
	0xfa, 0x1e, 0x6d, 0xa0, 0x03, 0x2e, 0x62, 0xa5, 0x49, 0x51, 0x4a, 0xf1, 0xd1, 0x7e, 0x13, 0xdd,
	0x70, 0x3e, 0x74, 0xbf, 0xc5, 0xac, 0x6f, 0xce, 0x1f, 0xfe, 0x08, 0x00, 0x00, 0xff, 0xff, 0x03,
	0x29, 0x7f, 0x18, 0x47, 0x03, 0x00, 0x00,
}

func (m *LogIntegration) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LogIntegration) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LogIntegration) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Config != nil {
		{
			size := m.Config.Size()
			i -= size
			if _, err := m.Config.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	if m.PollingInterval != nil {
		{
			size, err := m.PollingInterval.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintLogIntegration(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.CreatedAt != nil {
		{
			size, err := m.CreatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintLogIntegration(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintLogIntegration(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintLogIntegration(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *LogIntegration_EksConfig) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LogIntegration_EksConfig) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.EksConfig != nil {
		{
			size, err := m.EksConfig.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintLogIntegration(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	return len(dAtA) - i, nil
}
func (m *LogIntegration_GkeConfig) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LogIntegration_GkeConfig) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.GkeConfig != nil {
		{
			size, err := m.GkeConfig.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintLogIntegration(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	return len(dAtA) - i, nil
}
func (m *LogIntegration_AWSConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LogIntegration_AWSConfig) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LogIntegration_AWSConfig) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.SecretAccessKey) > 0 {
		i -= len(m.SecretAccessKey)
		copy(dAtA[i:], m.SecretAccessKey)
		i = encodeVarintLogIntegration(dAtA, i, uint64(len(m.SecretAccessKey)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.AccessKeyId) > 0 {
		i -= len(m.AccessKeyId)
		copy(dAtA[i:], m.AccessKeyId)
		i = encodeVarintLogIntegration(dAtA, i, uint64(len(m.AccessKeyId)))
		i--
		dAtA[i] = 0x12
	}
	if m.UseIam {
		i--
		if m.UseIam {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *LogIntegration_GCPConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LogIntegration_GCPConfig) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LogIntegration_GCPConfig) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.UseWorkloadId {
		i--
		if m.UseWorkloadId {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if len(m.ServiceAccount) > 0 {
		i -= len(m.ServiceAccount)
		copy(dAtA[i:], m.ServiceAccount)
		i = encodeVarintLogIntegration(dAtA, i, uint64(len(m.ServiceAccount)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintLogIntegration(dAtA []byte, offset int, v uint64) int {
	offset -= sovLogIntegration(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *LogIntegration) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	if m.CreatedAt != nil {
		l = m.CreatedAt.Size()
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	if m.PollingInterval != nil {
		l = m.PollingInterval.Size()
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	if m.Config != nil {
		n += m.Config.Size()
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *LogIntegration_EksConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.EksConfig != nil {
		l = m.EksConfig.Size()
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	return n
}
func (m *LogIntegration_GkeConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.GkeConfig != nil {
		l = m.GkeConfig.Size()
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	return n
}
func (m *LogIntegration_AWSConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.UseIam {
		n += 2
	}
	l = len(m.AccessKeyId)
	if l > 0 {
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	l = len(m.SecretAccessKey)
	if l > 0 {
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *LogIntegration_GCPConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ServiceAccount)
	if l > 0 {
		n += 1 + l + sovLogIntegration(uint64(l))
	}
	if m.UseWorkloadId {
		n += 2
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovLogIntegration(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozLogIntegration(x uint64) (n int) {
	return sovLogIntegration(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *LogIntegration) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLogIntegration
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
			return fmt.Errorf("proto: LogIntegration: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LogIntegration: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedAt == nil {
				m.CreatedAt = &types.Timestamp{}
			}
			if err := m.CreatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PollingInterval", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PollingInterval == nil {
				m.PollingInterval = &types.Duration{}
			}
			if err := m.PollingInterval.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EksConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &LogIntegration_AWSConfig{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Config = &LogIntegration_EksConfig{v}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field GkeConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &LogIntegration_GCPConfig{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Config = &LogIntegration_GkeConfig{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipLogIntegration(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthLogIntegration
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
func (m *LogIntegration_AWSConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLogIntegration
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
			return fmt.Errorf("proto: AWSConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AWSConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field UseIam", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
			m.UseIam = bool(v != 0)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessKeyId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessKeyId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SecretAccessKey", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SecretAccessKey = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipLogIntegration(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthLogIntegration
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
func (m *LogIntegration_GCPConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowLogIntegration
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
			return fmt.Errorf("proto: GCPConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GCPConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ServiceAccount", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
				return ErrInvalidLengthLogIntegration
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthLogIntegration
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ServiceAccount = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field UseWorkloadId", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowLogIntegration
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
			m.UseWorkloadId = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipLogIntegration(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthLogIntegration
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
func skipLogIntegration(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowLogIntegration
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
					return 0, ErrIntOverflowLogIntegration
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
					return 0, ErrIntOverflowLogIntegration
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
				return 0, ErrInvalidLengthLogIntegration
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupLogIntegration
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthLogIntegration
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthLogIntegration        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowLogIntegration          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupLogIntegration = fmt.Errorf("proto: unexpected end of group")
)
