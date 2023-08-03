// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/v1/product_usage_service.proto

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
	return fileDescriptor_851e532ab55b9ff5, []int{0}
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

type SecuredUnits struct {
	NumNodes             int64    `protobuf:"varint,1,opt,name=num_nodes,json=numNodes,proto3" json:"num_nodes,omitempty"`
	NumCpuUnits          int64    `protobuf:"varint,2,opt,name=num_cpu_units,json=numCpuUnits,proto3" json:"num_cpu_units,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecuredUnits) Reset()         { *m = SecuredUnits{} }
func (m *SecuredUnits) String() string { return proto.CompactTextString(m) }
func (*SecuredUnits) ProtoMessage()    {}
func (*SecuredUnits) Descriptor() ([]byte, []int) {
	return fileDescriptor_851e532ab55b9ff5, []int{1}
}
func (m *SecuredUnits) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SecuredUnits) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SecuredUnits.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SecuredUnits) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecuredUnits.Merge(m, src)
}
func (m *SecuredUnits) XXX_Size() int {
	return m.Size()
}
func (m *SecuredUnits) XXX_DiscardUnknown() {
	xxx_messageInfo_SecuredUnits.DiscardUnknown(m)
}

var xxx_messageInfo_SecuredUnits proto.InternalMessageInfo

func (m *SecuredUnits) GetNumNodes() int64 {
	if m != nil {
		return m.NumNodes
	}
	return 0
}

func (m *SecuredUnits) GetNumCpuUnits() int64 {
	if m != nil {
		return m.NumCpuUnits
	}
	return 0
}

func (m *SecuredUnits) MessageClone() proto.Message {
	return m.Clone()
}
func (m *SecuredUnits) Clone() *SecuredUnits {
	if m == nil {
		return nil
	}
	cloned := new(SecuredUnits)
	*cloned = *m

	return cloned
}

type CurrentProductUsageResponse struct {
	Timestamp            *types.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	SecuredUnits         *SecuredUnits    `protobuf:"bytes,2,opt,name=secured_units,json=securedUnits,proto3" json:"secured_units,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *CurrentProductUsageResponse) Reset()         { *m = CurrentProductUsageResponse{} }
func (m *CurrentProductUsageResponse) String() string { return proto.CompactTextString(m) }
func (*CurrentProductUsageResponse) ProtoMessage()    {}
func (*CurrentProductUsageResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_851e532ab55b9ff5, []int{2}
}
func (m *CurrentProductUsageResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CurrentProductUsageResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CurrentProductUsageResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CurrentProductUsageResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CurrentProductUsageResponse.Merge(m, src)
}
func (m *CurrentProductUsageResponse) XXX_Size() int {
	return m.Size()
}
func (m *CurrentProductUsageResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CurrentProductUsageResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CurrentProductUsageResponse proto.InternalMessageInfo

func (m *CurrentProductUsageResponse) GetTimestamp() *types.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

func (m *CurrentProductUsageResponse) GetSecuredUnits() *SecuredUnits {
	if m != nil {
		return m.SecuredUnits
	}
	return nil
}

func (m *CurrentProductUsageResponse) MessageClone() proto.Message {
	return m.Clone()
}
func (m *CurrentProductUsageResponse) Clone() *CurrentProductUsageResponse {
	if m == nil {
		return nil
	}
	cloned := new(CurrentProductUsageResponse)
	*cloned = *m

	cloned.Timestamp = m.Timestamp.Clone()
	cloned.SecuredUnits = m.SecuredUnits.Clone()
	return cloned
}

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
	return fileDescriptor_851e532ab55b9ff5, []int{3}
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
	proto.RegisterType((*SecuredUnits)(nil), "v1.SecuredUnits")
	proto.RegisterType((*CurrentProductUsageResponse)(nil), "v1.CurrentProductUsageResponse")
	proto.RegisterType((*MaxSecuredUnitsUsageResponse)(nil), "v1.MaxSecuredUnitsUsageResponse")
}

func init() {
	proto.RegisterFile("api/v1/product_usage_service.proto", fileDescriptor_851e532ab55b9ff5)
}

var fileDescriptor_851e532ab55b9ff5 = []byte{
	// 483 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x93, 0xcf, 0x6b, 0x13, 0x41,
	0x14, 0xc7, 0x9d, 0x4d, 0x91, 0xe6, 0x25, 0x81, 0x32, 0x8a, 0xc6, 0x4d, 0x49, 0xeb, 0x8a, 0x20,
	0x0a, 0xbb, 0x24, 0x22, 0x78, 0xf0, 0x52, 0x83, 0xf4, 0xe4, 0x0f, 0xb6, 0x2d, 0x88, 0x97, 0x65,
	0xba, 0x99, 0x2e, 0x0b, 0xce, 0x0f, 0x76, 0x66, 0xd6, 0x78, 0xf5, 0x0f, 0xf0, 0xe2, 0xc5, 0x3f,
	0xc9, 0xa3, 0xe0, 0x3f, 0x20, 0xd1, 0xff, 0xc1, 0xab, 0xcc, 0x4c, 0xb2, 0x6e, 0xb0, 0xb4, 0xbd,
	0xed, 0xdb, 0xef, 0xf7, 0xbd, 0x37, 0xef, 0x33, 0x6f, 0x20, 0x22, 0xb2, 0x4c, 0xea, 0x49, 0x22,
	0x2b, 0x31, 0x37, 0xb9, 0xce, 0x8c, 0x22, 0x05, 0xcd, 0x14, 0xad, 0xea, 0x32, 0xa7, 0xb1, 0xac,
	0x84, 0x16, 0x38, 0xa8, 0x27, 0x21, 0x5e, 0xf9, 0x28, 0x93, 0xfa, 0xa3, 0xff, 0x1f, 0xee, 0x16,
	0x42, 0x14, 0xef, 0x69, 0x62, 0x25, 0xc2, 0xb9, 0xd0, 0x44, 0x97, 0x82, 0xab, 0x95, 0xba, 0xb7,
	0x52, 0x5d, 0x74, 0x6a, 0xce, 0x12, 0x5d, 0x32, 0xaa, 0x34, 0x61, 0xd2, 0x1b, 0xa2, 0x02, 0xba,
	0xc7, 0x25, 0xa3, 0x29, 0xe1, 0x05, 0xc5, 0x31, 0x6c, 0x9d, 0x55, 0x82, 0x0d, 0xd1, 0x3e, 0x7a,
	0xd0, 0x9b, 0x86, 0xb1, 0x4f, 0x8e, 0xd7, 0xc9, 0xf1, 0xf1, 0x3a, 0x39, 0x75, 0x3e, 0xfc, 0x10,
	0x02, 0x2d, 0x86, 0xc1, 0xa5, 0xee, 0x40, 0x8b, 0xe8, 0x35, 0xf4, 0x8f, 0x68, 0x6e, 0x2a, 0x3a,
	0x3f, 0xe1, 0xa5, 0x56, 0x78, 0x04, 0x5d, 0x6e, 0x58, 0xc6, 0xc5, 0x9c, 0x2a, 0xd7, 0xb0, 0x93,
	0x6e, 0x73, 0xc3, 0x5e, 0xd9, 0x18, 0x47, 0x30, 0xb0, 0x62, 0x2e, 0x4d, 0x66, 0xac, 0xdb, 0xf5,
	0xe8, 0xa4, 0x3d, 0x6e, 0xd8, 0x4c, 0x1a, 0x57, 0x20, 0xfa, 0x8c, 0x60, 0x34, 0x33, 0x55, 0x45,
	0xb9, 0x7e, 0xe3, 0xb9, 0x9d, 0x58, 0x6c, 0x29, 0x55, 0x52, 0x70, 0x45, 0xf1, 0x53, 0xe8, 0x36,
	0xc3, 0x5e, 0x61, 0xa2, 0x7f, 0x66, 0xfc, 0x04, 0x06, 0xca, 0x1f, 0xb5, 0xd5, 0xbd, 0x37, 0xdd,
	0x89, 0xeb, 0x49, 0xdc, 0x9e, 0x21, 0xed, 0xab, 0x56, 0x14, 0x2d, 0x11, 0xec, 0xbe, 0x24, 0x8b,
	0xb6, 0x63, 0xf3, 0x44, 0xcf, 0xa0, 0xcf, 0xc8, 0xc2, 0x8f, 0x9c, 0x11, 0x7d, 0x85, 0x43, 0x01,
	0x23, 0x0b, 0x47, 0xe4, 0x40, 0x5b, 0x60, 0x4d, 0xf6, 0x8a, 0xc7, 0xf6, 0x5a, 0xc6, 0x33, 0xd8,
	0xb1, 0x62, 0x03, 0xcc, 0x96, 0xef, 0x5c, 0x5a, 0x7e, 0xc0, 0xc8, 0x62, 0xcd, 0xf3, 0x40, 0x5b,
	0xea, 0x1b, 0x45, 0x86, 0x5b, 0x9e, 0x7a, 0xcb, 0x35, 0xfd, 0x83, 0xe0, 0x46, 0x1b, 0xf7, 0x91,
	0x5f, 0x52, 0x5c, 0xc0, 0xad, 0x43, 0xaa, 0xcf, 0xb9, 0x0f, 0xdc, 0xb5, 0xd8, 0x5e, 0xd8, 0x8d,
	0x0d, 0xf7, 0xec, 0xe7, 0x05, 0x77, 0x16, 0xdd, 0xfd, 0xf4, 0xe3, 0xf7, 0x97, 0x60, 0x84, 0xef,
	0xb4, 0x5e, 0x43, 0xe2, 0x5e, 0x43, 0x92, 0xfb, 0x34, 0xfc, 0x01, 0x6e, 0x1f, 0x52, 0x7d, 0x1e,
	0x67, 0x3c, 0xb0, 0xe5, 0x9b, 0x6d, 0x0e, 0xf7, 0x6d, 0x78, 0xd1, 0x85, 0x44, 0x8f, 0x5c, 0xbb,
	0xfb, 0xf8, 0xde, 0xff, 0xed, 0x2c, 0x88, 0x8d, 0x25, 0x78, 0x7e, 0xf3, 0xdb, 0x72, 0x8c, 0xbe,
	0x2f, 0xc7, 0xe8, 0xe7, 0x72, 0x8c, 0xbe, 0xfe, 0x1a, 0x5f, 0x7b, 0x17, 0xd4, 0x93, 0xb7, 0xe8,
	0xf4, 0xba, 0x03, 0xfb, 0xf8, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x17, 0xdf, 0xe3, 0x14, 0xc5,
	0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ProductUsageServiceClient is the client API for ProductUsageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConnInterface.NewStream.
type ProductUsageServiceClient interface {
	// GetCurrentProductUsage
	//
	// Returns current usage, with about 5 minutes accuracy.
	GetCurrentProductUsage(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CurrentProductUsageResponse, error)
	// GetMaxSecuredUnitsUsage
	//
	// Returns maximum, i.e. peak, usage for the given time frame together
	// with the time when this maximum was observed.
	GetMaxSecuredUnitsUsage(ctx context.Context, in *TimeRange, opts ...grpc.CallOption) (*MaxSecuredUnitsUsageResponse, error)
}

type productUsageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewProductUsageServiceClient(cc grpc.ClientConnInterface) ProductUsageServiceClient {
	return &productUsageServiceClient{cc}
}

func (c *productUsageServiceClient) GetCurrentProductUsage(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CurrentProductUsageResponse, error) {
	out := new(CurrentProductUsageResponse)
	err := c.cc.Invoke(ctx, "/v1.ProductUsageService/GetCurrentProductUsage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *productUsageServiceClient) GetMaxSecuredUnitsUsage(ctx context.Context, in *TimeRange, opts ...grpc.CallOption) (*MaxSecuredUnitsUsageResponse, error) {
	out := new(MaxSecuredUnitsUsageResponse)
	err := c.cc.Invoke(ctx, "/v1.ProductUsageService/GetMaxSecuredUnitsUsage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProductUsageServiceServer is the server API for ProductUsageService service.
type ProductUsageServiceServer interface {
	// GetCurrentProductUsage
	//
	// Returns current usage, with about 5 minutes accuracy.
	GetCurrentProductUsage(context.Context, *Empty) (*CurrentProductUsageResponse, error)
	// GetMaxSecuredUnitsUsage
	//
	// Returns maximum, i.e. peak, usage for the given time frame together
	// with the time when this maximum was observed.
	GetMaxSecuredUnitsUsage(context.Context, *TimeRange) (*MaxSecuredUnitsUsageResponse, error)
}

// UnimplementedProductUsageServiceServer can be embedded to have forward compatible implementations.
type UnimplementedProductUsageServiceServer struct {
}

func (*UnimplementedProductUsageServiceServer) GetCurrentProductUsage(ctx context.Context, req *Empty) (*CurrentProductUsageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCurrentProductUsage not implemented")
}
func (*UnimplementedProductUsageServiceServer) GetMaxSecuredUnitsUsage(ctx context.Context, req *TimeRange) (*MaxSecuredUnitsUsageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMaxSecuredUnitsUsage not implemented")
}

func RegisterProductUsageServiceServer(s *grpc.Server, srv ProductUsageServiceServer) {
	s.RegisterService(&_ProductUsageService_serviceDesc, srv)
}

func _ProductUsageService_GetCurrentProductUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProductUsageServiceServer).GetCurrentProductUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.ProductUsageService/GetCurrentProductUsage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProductUsageServiceServer).GetCurrentProductUsage(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _ProductUsageService_GetMaxSecuredUnitsUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TimeRange)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProductUsageServiceServer).GetMaxSecuredUnitsUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.ProductUsageService/GetMaxSecuredUnitsUsage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProductUsageServiceServer).GetMaxSecuredUnitsUsage(ctx, req.(*TimeRange))
	}
	return interceptor(ctx, in, info, handler)
}

var _ProductUsageService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "v1.ProductUsageService",
	HandlerType: (*ProductUsageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCurrentProductUsage",
			Handler:    _ProductUsageService_GetCurrentProductUsage_Handler,
		},
		{
			MethodName: "GetMaxSecuredUnitsUsage",
			Handler:    _ProductUsageService_GetMaxSecuredUnitsUsage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/product_usage_service.proto",
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
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
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
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *SecuredUnits) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SecuredUnits) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SecuredUnits) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.NumCpuUnits != 0 {
		i = encodeVarintProductUsageService(dAtA, i, uint64(m.NumCpuUnits))
		i--
		dAtA[i] = 0x10
	}
	if m.NumNodes != 0 {
		i = encodeVarintProductUsageService(dAtA, i, uint64(m.NumNodes))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *CurrentProductUsageResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CurrentProductUsageResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CurrentProductUsageResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.SecuredUnits != nil {
		{
			size, err := m.SecuredUnits.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Timestamp != nil {
		{
			size, err := m.Timestamp.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
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
		i = encodeVarintProductUsageService(dAtA, i, uint64(m.MaxCpuUnits))
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
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.MaxNodes != 0 {
		i = encodeVarintProductUsageService(dAtA, i, uint64(m.MaxNodes))
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
			i = encodeVarintProductUsageService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintProductUsageService(dAtA []byte, offset int, v uint64) int {
	offset -= sovProductUsageService(v)
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
		n += 1 + l + sovProductUsageService(uint64(l))
	}
	if m.To != nil {
		l = m.To.Size()
		n += 1 + l + sovProductUsageService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *SecuredUnits) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.NumNodes != 0 {
		n += 1 + sovProductUsageService(uint64(m.NumNodes))
	}
	if m.NumCpuUnits != 0 {
		n += 1 + sovProductUsageService(uint64(m.NumCpuUnits))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CurrentProductUsageResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Timestamp != nil {
		l = m.Timestamp.Size()
		n += 1 + l + sovProductUsageService(uint64(l))
	}
	if m.SecuredUnits != nil {
		l = m.SecuredUnits.Size()
		n += 1 + l + sovProductUsageService(uint64(l))
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
		n += 1 + l + sovProductUsageService(uint64(l))
	}
	if m.MaxNodes != 0 {
		n += 1 + sovProductUsageService(uint64(m.MaxNodes))
	}
	if m.MaxCpuUnitsAt != nil {
		l = m.MaxCpuUnitsAt.Size()
		n += 1 + l + sovProductUsageService(uint64(l))
	}
	if m.MaxCpuUnits != 0 {
		n += 1 + sovProductUsageService(uint64(m.MaxCpuUnits))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovProductUsageService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozProductUsageService(x uint64) (n int) {
	return sovProductUsageService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TimeRange) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProductUsageService
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
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
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
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
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
			skippy, err := skipProductUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthProductUsageService
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
func (m *SecuredUnits) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProductUsageService
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
			return fmt.Errorf("proto: SecuredUnits: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SecuredUnits: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NumNodes", wireType)
			}
			m.NumNodes = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsageService
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
					return ErrIntOverflowProductUsageService
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
			skippy, err := skipProductUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthProductUsageService
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
func (m *CurrentProductUsageResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProductUsageService
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
			return fmt.Errorf("proto: CurrentProductUsageResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CurrentProductUsageResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Timestamp == nil {
				m.Timestamp = &types.Timestamp{}
			}
			if err := m.Timestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SecuredUnits", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.SecuredUnits == nil {
				m.SecuredUnits = &SecuredUnits{}
			}
			if err := m.SecuredUnits.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProductUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthProductUsageService
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
				return ErrIntOverflowProductUsageService
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
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
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
					return ErrIntOverflowProductUsageService
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
					return ErrIntOverflowProductUsageService
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
				return ErrInvalidLengthProductUsageService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProductUsageService
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
					return ErrIntOverflowProductUsageService
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
			skippy, err := skipProductUsageService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthProductUsageService
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
func skipProductUsageService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowProductUsageService
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
					return 0, ErrIntOverflowProductUsageService
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
					return 0, ErrIntOverflowProductUsageService
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
				return 0, ErrInvalidLengthProductUsageService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupProductUsageService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthProductUsageService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthProductUsageService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowProductUsageService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupProductUsageService = fmt.Errorf("proto: unexpected end of group")
)
