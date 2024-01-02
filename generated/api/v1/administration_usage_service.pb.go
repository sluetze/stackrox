// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/v1/administration_usage_service.proto

package v1

import (
	context "context"
	fmt "fmt"
	types "github.com/gogo/protobuf/types"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

// TimeRange allows for requesting data by a time range.
type TimeRange struct {
	From                 *types.Timestamp `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	To                   *types.Timestamp `protobuf:"bytes,2,opt,name=to,proto3" json:"to,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *TimeRange) Reset()         { *m = TimeRange{} }
func (m *TimeRange) String() string { return proto.CompactTextString(m) }
func (*TimeRange) ProtoMessage()    {}
func (*TimeRange) Descriptor() ([]byte, []int) {
	return fileDescriptor_4e7d8a93856728d1, []int{0}
}
func (m *TimeRange) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TimeRange) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TimeRange.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *TimeRange) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TimeRange.Merge(m, src)
}
func (m *TimeRange) XXX_Size() int {
	return m.Size()
}
func (m *TimeRange) XXX_DiscardUnknown() {
	xxx_messageInfo_TimeRange.DiscardUnknown(m)
}

var xxx_messageInfo_TimeRange proto.InternalMessageInfo

func (m *TimeRange) GetFrom() *types.Timestamp {
	if m != nil {
		return m.From
	}
	return nil
}

func (m *TimeRange) GetTo() *types.Timestamp {
	if m != nil {
		return m.To
	}
	return nil
}

func (m *TimeRange) MessageClone() proto.Message {
	return m.Clone()
}
func (m *TimeRange) Clone() *TimeRange {
	if m == nil {
		return nil
	}
	cloned := new(TimeRange)
	*cloned = *m

	cloned.From = m.From.Clone()
	cloned.To = m.To.Clone()
	return cloned
}

// SecuredUnitsUsageResponse holds the values of the currently observable
// administration usage metrics.
type SecuredUnitsUsageResponse struct {
	NumNodes             int64    `protobuf:"varint,1,opt,name=num_nodes,json=numNodes,proto3" json:"num_nodes,omitempty"`
	NumCpuUnits          int64    `protobuf:"varint,2,opt,name=num_cpu_units,json=numCpuUnits,proto3" json:"num_cpu_units,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecuredUnitsUsageResponse) Reset()         { *m = SecuredUnitsUsageResponse{} }
func (m *SecuredUnitsUsageResponse) String() string { return proto.CompactTextString(m) }
func (*SecuredUnitsUsageResponse) ProtoMessage()    {}
func (*SecuredUnitsUsageResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_4e7d8a93856728d1, []int{1}
}
func (m *SecuredUnitsUsageResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SecuredUnitsUsageResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SecuredUnitsUsageResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SecuredUnitsUsageResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecuredUnitsUsageResponse.Merge(m, src)
}
func (m *SecuredUnitsUsageResponse) XXX_Size() int {
	return m.Size()
}
func (m *SecuredUnitsUsageResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SecuredUnitsUsageResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SecuredUnitsUsageResponse proto.InternalMessageInfo

func (m *SecuredUnitsUsageResponse) GetNumNodes() int64 {
	if m != nil {
		return m.NumNodes
	}
	return 0
}

func (m *SecuredUnitsUsageResponse) GetNumCpuUnits() int64 {
	if m != nil {
		return m.NumCpuUnits
	}
	return 0
}

func (m *SecuredUnitsUsageResponse) MessageClone() proto.Message {
	return m.Clone()
}
func (m *SecuredUnitsUsageResponse) Clone() *SecuredUnitsUsageResponse {
	if m == nil {
		return nil
	}
	cloned := new(SecuredUnitsUsageResponse)
	*cloned = *m

	return cloned
}

// MaxSecuredUnitsUsageResponse holds the maximum values of the secured nodes
// and CPU Units (as reported by Kubernetes) with the time at which these
// values were aggregated, with the aggregation period accuracy (1h).
type MaxSecuredUnitsUsageResponse struct {
	MaxNodesAt           *types.Timestamp `protobuf:"bytes,1,opt,name=max_nodes_at,json=maxNodesAt,proto3" json:"max_nodes_at,omitempty"`
	MaxNodes             int64            `protobuf:"varint,2,opt,name=max_nodes,json=maxNodes,proto3" json:"max_nodes,omitempty"`
	MaxCpuUnitsAt        *types.Timestamp `protobuf:"bytes,3,opt,name=max_cpu_units_at,json=maxCpuUnitsAt,proto3" json:"max_cpu_units_at,omitempty"`
	MaxCpuUnits          int64            `protobuf:"varint,4,opt,name=max_cpu_units,json=maxCpuUnits,proto3" json:"max_cpu_units,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *MaxSecuredUnitsUsageResponse) Reset()         { *m = MaxSecuredUnitsUsageResponse{} }
func (m *MaxSecuredUnitsUsageResponse) String() string { return proto.CompactTextString(m) }
func (*MaxSecuredUnitsUsageResponse) ProtoMessage()    {}
func (*MaxSecuredUnitsUsageResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_4e7d8a93856728d1, []int{2}
}
func (m *MaxSecuredUnitsUsageResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MaxSecuredUnitsUsageResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MaxSecuredUnitsUsageResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MaxSecuredUnitsUsageResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MaxSecuredUnitsUsageResponse.Merge(m, src)
}
func (m *MaxSecuredUnitsUsageResponse) XXX_Size() int {
	return m.Size()
}
func (m *MaxSecuredUnitsUsageResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MaxSecuredUnitsUsageResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MaxSecuredUnitsUsageResponse proto.InternalMessageInfo

func (m *MaxSecuredUnitsUsageResponse) GetMaxNodesAt() *types.Timestamp {
	if m != nil {
		return m.MaxNodesAt
	}
	return nil
}

func (m *MaxSecuredUnitsUsageResponse) GetMaxNodes() int64 {
	if m != nil {
		return m.MaxNodes
	}
	return 0
}

func (m *MaxSecuredUnitsUsageResponse) GetMaxCpuUnitsAt() *types.Timestamp {
	if m != nil {
		return m.MaxCpuUnitsAt
	}
	return nil
}

func (m *MaxSecuredUnitsUsageResponse) GetMaxCpuUnits() int64 {
	if m != nil {
		return m.MaxCpuUnits
	}
	return 0
}

func (m *MaxSecuredUnitsUsageResponse) MessageClone() proto.Message {
	return m.Clone()
}
func (m *MaxSecuredUnitsUsageResponse) Clone() *MaxSecuredUnitsUsageResponse {
	if m == nil {
		return nil
	}
	cloned := new(MaxSecuredUnitsUsageResponse)
	*cloned = *m

	cloned.MaxNodesAt = m.MaxNodesAt.Clone()
	cloned.MaxCpuUnitsAt = m.MaxCpuUnitsAt.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*TimeRange)(nil), "v1.TimeRange")
	proto.RegisterType((*SecuredUnitsUsageResponse)(nil), "v1.SecuredUnitsUsageResponse")
	proto.RegisterType((*MaxSecuredUnitsUsageResponse)(nil), "v1.MaxSecuredUnitsUsageResponse")
}

func init() {
	proto.RegisterFile("api/v1/administration_usage_service.proto", fileDescriptor_4e7d8a93856728d1)
}

var fileDescriptor_4e7d8a93856728d1 = []byte{
	// 466 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x4d, 0x6f, 0xd4, 0x30,
	0x10, 0x6d, 0xb2, 0x15, 0xea, 0xba, 0xac, 0x84, 0x7c, 0x61, 0x49, 0xcb, 0x52, 0xe5, 0x04, 0x15,
	0x38, 0x64, 0x91, 0x38, 0x71, 0x59, 0x56, 0xa8, 0x27, 0x38, 0xa4, 0xad, 0x84, 0x10, 0x52, 0xe4,
	0x66, 0xdd, 0xc8, 0x02, 0xdb, 0x91, 0x3d, 0x8e, 0xc2, 0x05, 0x24, 0xfe, 0x02, 0x17, 0x2e, 0xfc,
	0x1f, 0x8e, 0x48, 0xfc, 0x01, 0xb4, 0xf0, 0x43, 0x90, 0xed, 0xcd, 0x8a, 0xaa, 0xf4, 0xe3, 0x96,
	0xc9, 0xbc, 0x37, 0xef, 0x8d, 0xe7, 0xa1, 0x07, 0xb4, 0xe1, 0x59, 0x9b, 0x67, 0x74, 0x21, 0xb8,
	0xe4, 0x06, 0x34, 0x05, 0xae, 0x64, 0x69, 0x0d, 0xad, 0x59, 0x69, 0x98, 0x6e, 0x79, 0xc5, 0x48,
	0xa3, 0x15, 0x28, 0x1c, 0xb7, 0x79, 0xb2, 0x5b, 0x2b, 0x55, 0xbf, 0x67, 0x99, 0x63, 0x51, 0x29,
	0x15, 0x78, 0xb8, 0x09, 0x88, 0x04, 0xaf, 0x86, 0x31, 0xd1, 0xc0, 0x87, 0xd5, 0xbf, 0x7b, 0x2b,
	0x86, 0xaf, 0x4e, 0xec, 0x69, 0x06, 0x5c, 0x30, 0x03, 0x54, 0x34, 0x01, 0x90, 0xd6, 0x68, 0x78,
	0xc4, 0x05, 0x2b, 0xa8, 0xac, 0x19, 0x26, 0x68, 0xf3, 0x54, 0x2b, 0x31, 0x8e, 0xf6, 0xa2, 0xfb,
	0xdb, 0xd3, 0x84, 0x04, 0x32, 0xe9, 0xc9, 0xe4, 0xa8, 0x27, 0x17, 0x1e, 0x87, 0xf7, 0x51, 0x0c,
	0x6a, 0x1c, 0x5f, 0x89, 0x8e, 0x41, 0xa5, 0x6f, 0xd1, 0x9d, 0x43, 0x56, 0x59, 0xcd, 0x16, 0xc7,
	0x92, 0x83, 0x39, 0x76, 0x2b, 0x16, 0xcc, 0x34, 0x4a, 0x1a, 0x86, 0x77, 0xd0, 0x50, 0x5a, 0x51,
	0x4a, 0xb5, 0x60, 0xc6, 0xab, 0x0f, 0x8a, 0x2d, 0x69, 0xc5, 0x2b, 0x57, 0xe3, 0x14, 0x8d, 0x5c,
	0xb3, 0x6a, 0x6c, 0x69, 0x1d, 0xd5, 0x0b, 0x0e, 0x8a, 0x6d, 0x69, 0xc5, 0xbc, 0xb1, 0x7e, 0x5a,
	0xba, 0x8c, 0xd0, 0xee, 0x4b, 0xda, 0x5d, 0xac, 0xf0, 0x0c, 0xdd, 0x14, 0xb4, 0x0b, 0x0a, 0x25,
	0x85, 0x6b, 0xac, 0x88, 0x04, 0xed, 0xbc, 0x81, 0x19, 0x38, 0x7f, 0x6b, 0xf6, 0x4a, 0x7e, 0xab,
	0x6f, 0xe3, 0x39, 0xba, 0xe5, 0x9a, 0x6b, 0x7f, 0x6e, 0xfc, 0xe0, 0xca, 0xf1, 0x23, 0x41, 0xbb,
	0xde, 0xfe, 0x0c, 0xdc, 0x92, 0x67, 0x86, 0x8c, 0x37, 0xc3, 0x92, 0xff, 0xa0, 0xa6, 0xdf, 0x62,
	0x94, 0xcc, 0xce, 0x24, 0xc5, 0xef, 0x78, 0x18, 0x72, 0x82, 0x3f, 0xa1, 0x9d, 0x03, 0x06, 0x73,
	0xab, 0x35, 0x93, 0x70, 0xee, 0x25, 0xf0, 0x90, 0xb4, 0x39, 0x79, 0xe1, 0xb2, 0x91, 0xdc, 0x75,
	0x9f, 0x17, 0xbe, 0x55, 0xfa, 0xf4, 0xf3, 0xcf, 0x3f, 0x5f, 0xe2, 0xc7, 0x98, 0x9c, 0x8f, 0x66,
	0xe6, 0xa3, 0x99, 0x99, 0xc0, 0x7d, 0xe4, 0xad, 0x66, 0x55, 0x90, 0xc4, 0x1f, 0xd1, 0xed, 0x03,
	0x06, 0xff, 0x3b, 0x03, 0x1e, 0x39, 0xc5, 0x75, 0xd0, 0x92, 0x3d, 0x57, 0x5e, 0x76, 0xaf, 0x74,
	0xea, 0x3d, 0x3c, 0xc4, 0xfb, 0xd7, 0xf4, 0x20, 0x68, 0xf7, 0x9c, 0x7c, 0x5f, 0x4e, 0xa2, 0x1f,
	0xcb, 0x49, 0xf4, 0x6b, 0x39, 0x89, 0xbe, 0xfe, 0x9e, 0x6c, 0xa0, 0x31, 0x57, 0xc4, 0x00, 0xad,
	0xde, 0x69, 0xd5, 0x85, 0x23, 0x10, 0xda, 0x70, 0xd2, 0xe6, 0x6f, 0xe2, 0x36, 0x7f, 0xbd, 0x71,
	0x72, 0xc3, 0xff, 0x7b, 0xf2, 0x37, 0x00, 0x00, 0xff, 0xff, 0x56, 0x28, 0x1b, 0x0a, 0x88, 0x03,
	0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// AdministrationUsageServiceClient is the client API for AdministrationUsageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConnInterface.NewStream.
type AdministrationUsageServiceClient interface {
	// GetCurrentSecuredUnitsUsage returns the current secured units usage
	// metrics values.
	//
	// The secured units metrics are collected from all connected clusters every
	// 5 minutes, so the returned result includes data for the connected
	// clusters accurate to about these 5 minutes, and potentially some outdated
	// data for the disconnected clusters.
	GetCurrentSecuredUnitsUsage(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SecuredUnitsUsageResponse, error)
	// GetMaxSecuredUnitsUsage returns the maximum, i.e. peak, secured units
	// usage observed during a given time range, together with the time when
	// this maximum was aggregated and stored.
	//
	// The usage metrics are continuously collected from all the connected
	// clusters. The maximum values are kept for some period of time in memory,
	// and then, periodically, are stored to the database.
	// The last data from disconnected clusters are taken into account.
	GetMaxSecuredUnitsUsage(ctx context.Context, in *TimeRange, opts ...grpc.CallOption) (*MaxSecuredUnitsUsageResponse, error)
}

type administrationUsageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAdministrationUsageServiceClient(cc grpc.ClientConnInterface) AdministrationUsageServiceClient {
	return &administrationUsageServiceClient{cc}
}

func (c *administrationUsageServiceClient) GetCurrentSecuredUnitsUsage(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SecuredUnitsUsageResponse, error) {
	out := new(SecuredUnitsUsageResponse)
	err := c.cc.Invoke(ctx, "/v1.AdministrationUsageService/GetCurrentSecuredUnitsUsage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *administrationUsageServiceClient) GetMaxSecuredUnitsUsage(ctx context.Context, in *TimeRange, opts ...grpc.CallOption) (*MaxSecuredUnitsUsageResponse, error) {
	out := new(MaxSecuredUnitsUsageResponse)
	err := c.cc.Invoke(ctx, "/v1.AdministrationUsageService/GetMaxSecuredUnitsUsage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdministrationUsageServiceServer is the server API for AdministrationUsageService service.
type AdministrationUsageServiceServer interface {
	// GetCurrentSecuredUnitsUsage returns the current secured units usage
	// metrics values.
	//
	// The secured units metrics are collected from all connected clusters every
	// 5 minutes, so the returned result includes data for the connected
	// clusters accurate to about these 5 minutes, and potentially some outdated
	// data for the disconnected clusters.
	GetCurrentSecuredUnitsUsage(context.Context, *Empty) (*SecuredUnitsUsageResponse, error)
	// GetMaxSecuredUnitsUsage returns the maximum, i.e. peak, secured units
	// usage observed during a given time range, together with the time when
	// this maximum was aggregated and stored.
	//
	// The usage metrics are continuously collected from all the connected
	// clusters. The maximum values are kept for some period of time in memory,
	// and then, periodically, are stored to the database.
	// The last data from disconnected clusters are taken into account.
	GetMaxSecuredUnitsUsage(context.Context, *TimeRange) (*MaxSecuredUnitsUsageResponse, error)
}

// UnimplementedAdministrationUsageServiceServer can be embedded to have forward compatible implementations.
type UnimplementedAdministrationUsageServiceServer struct {
}

func (*UnimplementedAdministrationUsageServiceServer) GetCurrentSecuredUnitsUsage(ctx context.Context, req *Empty) (*SecuredUnitsUsageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCurrentSecuredUnitsUsage not implemented")
}
func (*UnimplementedAdministrationUsageServiceServer) GetMaxSecuredUnitsUsage(ctx context.Context, req *TimeRange) (*MaxSecuredUnitsUsageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMaxSecuredUnitsUsage not implemented")
}

func RegisterAdministrationUsageServiceServer(s *grpc.Server, srv AdministrationUsageServiceServer) {
	s.RegisterService(&_AdministrationUsageService_serviceDesc, srv)
}

func _AdministrationUsageService_GetCurrentSecuredUnitsUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdministrationUsageServiceServer).GetCurrentSecuredUnitsUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.AdministrationUsageService/GetCurrentSecuredUnitsUsage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdministrationUsageServiceServer).GetCurrentSecuredUnitsUsage(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _AdministrationUsageService_GetMaxSecuredUnitsUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TimeRange)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AdministrationUsageServiceServer).GetMaxSecuredUnitsUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.AdministrationUsageService/GetMaxSecuredUnitsUsage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AdministrationUsageServiceServer).GetMaxSecuredUnitsUsage(ctx, req.(*TimeRange))
	}
	return interceptor(ctx, in, info, handler)
}

var _AdministrationUsageService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "v1.AdministrationUsageService",
	HandlerType: (*AdministrationUsageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCurrentSecuredUnitsUsage",
			Handler:    _AdministrationUsageService_GetCurrentSecuredUnitsUsage_Handler,
		},
		{
			MethodName: "GetMaxSecuredUnitsUsage",
			Handler:    _AdministrationUsageService_GetMaxSecuredUnitsUsage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/administration_usage_service.proto",
}

func (m *TimeRange) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TimeRange) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *TimeRange) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.To != nil {
		{
			size, err := m.To.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAdministrationUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.From != nil {
		{
			size, err := m.From.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAdministrationUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *SecuredUnitsUsageResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SecuredUnitsUsageResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SecuredUnitsUsageResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.NumCpuUnits != 0 {
		i = encodeVarintAdministrationUsageService(dAtA, i, uint64(m.NumCpuUnits))
		i--
		dAtA[i] = 0x10
	}
	if m.NumNodes != 0 {
		i = encodeVarintAdministrationUsageService(dAtA, i, uint64(m.NumNodes))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *MaxSecuredUnitsUsageResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MaxSecuredUnitsUsageResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MaxSecuredUnitsUsageResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.MaxCpuUnits != 0 {
		i = encodeVarintAdministrationUsageService(dAtA, i, uint64(m.MaxCpuUnits))
		i--
		dAtA[i] = 0x20
	}
	if m.MaxCpuUnitsAt != nil {
		{
			size, err := m.MaxCpuUnitsAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAdministrationUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.MaxNodes != 0 {
		i = encodeVarintAdministrationUsageService(dAtA, i, uint64(m.MaxNodes))
		i--
		dAtA[i] = 0x10
	}
	if m.MaxNodesAt != nil {
		{
			size, err := m.MaxNodesAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAdministrationUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintAdministrationUsageService(dAtA []byte, offset int, v uint64) int {
	offset -= sovAdministrationUsageService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *TimeRange) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.From != nil {
		l = m.From.Size()
		n += 1 + l + sovAdministrationUsageService(uint64(l))
	}
	if m.To != nil {
		l = m.To.Size()
		n += 1 + l + sovAdministrationUsageService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *SecuredUnitsUsageResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.NumNodes != 0 {
		n += 1 + sovAdministrationUsageService(uint64(m.NumNodes))
	}
	if m.NumCpuUnits != 0 {
		n += 1 + sovAdministrationUsageService(uint64(m.NumCpuUnits))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *MaxSecuredUnitsUsageResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.MaxNodesAt != nil {
		l = m.MaxNodesAt.Size()
		n += 1 + l + sovAdministrationUsageService(uint64(l))
	}
	if m.MaxNodes != 0 {
		n += 1 + sovAdministrationUsageService(uint64(m.MaxNodes))
	}
	if m.MaxCpuUnitsAt != nil {
		l = m.MaxCpuUnitsAt.Size()
		n += 1 + l + sovAdministrationUsageService(uint64(l))
	}
	if m.MaxCpuUnits != 0 {
		n += 1 + sovAdministrationUsageService(uint64(m.MaxCpuUnits))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovAdministrationUsageService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAdministrationUsageService(x uint64) (n int) {
	return sovAdministrationUsageService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TimeRange) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAdministrationUsageService
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
			return fmt.Errorf("proto: TimeRange: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TimeRange: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field From", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
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
				return ErrInvalidLengthAdministrationUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAdministrationUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.From == nil {
				m.From = &types.Timestamp{}
			}
			if err := m.From.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field To", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
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
				return ErrInvalidLengthAdministrationUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAdministrationUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.To == nil {
				m.To = &types.Timestamp{}
			}
			if err := m.To.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAdministrationUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAdministrationUsageService
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
func (m *SecuredUnitsUsageResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAdministrationUsageService
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
			return fmt.Errorf("proto: SecuredUnitsUsageResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SecuredUnitsUsageResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumNodes", wireType)
			}
			m.NumNodes = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NumNodes |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumCpuUnits", wireType)
			}
			m.NumCpuUnits = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.NumCpuUnits |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipAdministrationUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAdministrationUsageService
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
func (m *MaxSecuredUnitsUsageResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAdministrationUsageService
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
			return fmt.Errorf("proto: MaxSecuredUnitsUsageResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MaxSecuredUnitsUsageResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxNodesAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
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
				return ErrInvalidLengthAdministrationUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAdministrationUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxNodesAt == nil {
				m.MaxNodesAt = &types.Timestamp{}
			}
			if err := m.MaxNodesAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxNodes", wireType)
			}
			m.MaxNodes = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxNodes |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxCpuUnitsAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
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
				return ErrInvalidLengthAdministrationUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAdministrationUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MaxCpuUnitsAt == nil {
				m.MaxCpuUnitsAt = &types.Timestamp{}
			}
			if err := m.MaxCpuUnitsAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxCpuUnits", wireType)
			}
			m.MaxCpuUnits = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAdministrationUsageService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxCpuUnits |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipAdministrationUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAdministrationUsageService
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
func skipAdministrationUsageService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAdministrationUsageService
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
					return 0, ErrIntOverflowAdministrationUsageService
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
					return 0, ErrIntOverflowAdministrationUsageService
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
				return 0, ErrInvalidLengthAdministrationUsageService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAdministrationUsageService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAdministrationUsageService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAdministrationUsageService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAdministrationUsageService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAdministrationUsageService = fmt.Errorf("proto: unexpected end of group")
)
