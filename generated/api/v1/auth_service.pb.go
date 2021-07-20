// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/v1/auth_service.proto

package v1

import (
	context "context"
	fmt "fmt"
	types "github.com/gogo/protobuf/types"
	proto "github.com/golang/protobuf/proto"
	storage "github.com/stackrox/rox/generated/storage"
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

type UserAttribute struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Values               []string `protobuf:"bytes,2,rep,name=values,proto3" json:"values,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UserAttribute) Reset()         { *m = UserAttribute{} }
func (m *UserAttribute) String() string { return proto.CompactTextString(m) }
func (*UserAttribute) ProtoMessage()    {}
func (*UserAttribute) Descriptor() ([]byte, []int) {
	return fileDescriptor_70ce5d1cdb6bc92a, []int{0}
}
func (m *UserAttribute) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *UserAttribute) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_UserAttribute.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *UserAttribute) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserAttribute.Merge(m, src)
}
func (m *UserAttribute) XXX_Size() int {
	return m.Size()
}
func (m *UserAttribute) XXX_DiscardUnknown() {
	xxx_messageInfo_UserAttribute.DiscardUnknown(m)
}

var xxx_messageInfo_UserAttribute proto.InternalMessageInfo

func (m *UserAttribute) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *UserAttribute) GetValues() []string {
	if m != nil {
		return m.Values
	}
	return nil
}

func (m *UserAttribute) MessageClone() proto.Message {
	return m.Clone()
}
func (m *UserAttribute) Clone() *UserAttribute {
	if m == nil {
		return nil
	}
	cloned := new(UserAttribute)
	*cloned = *m

	if m.Values != nil {
		cloned.Values = make([]string, len(m.Values))
		copy(cloned.Values, m.Values)
	}
	return cloned
}

type AuthStatus struct {
	// Types that are valid to be assigned to Id:
	//	*AuthStatus_UserId
	//	*AuthStatus_ServiceId
	Id                   isAuthStatus_Id       `protobuf_oneof:"id"`
	Expires              *types.Timestamp      `protobuf:"bytes,3,opt,name=expires,proto3" json:"expires,omitempty"`
	RefreshUrl           string                `protobuf:"bytes,4,opt,name=refresh_url,json=refreshUrl,proto3" json:"refresh_url,omitempty"`
	AuthProvider         *storage.AuthProvider `protobuf:"bytes,5,opt,name=auth_provider,json=authProvider,proto3" json:"auth_provider,omitempty"`
	UserInfo             *storage.UserInfo     `protobuf:"bytes,6,opt,name=user_info,json=userInfo,proto3" json:"user_info,omitempty"`
	UserAttributes       []*UserAttribute      `protobuf:"bytes,7,rep,name=user_attributes,json=userAttributes,proto3" json:"user_attributes,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *AuthStatus) Reset()         { *m = AuthStatus{} }
func (m *AuthStatus) String() string { return proto.CompactTextString(m) }
func (*AuthStatus) ProtoMessage()    {}
func (*AuthStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_70ce5d1cdb6bc92a, []int{1}
}
func (m *AuthStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AuthStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AuthStatus.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AuthStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthStatus.Merge(m, src)
}
func (m *AuthStatus) XXX_Size() int {
	return m.Size()
}
func (m *AuthStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthStatus.DiscardUnknown(m)
}

var xxx_messageInfo_AuthStatus proto.InternalMessageInfo

type isAuthStatus_Id interface {
	isAuthStatus_Id()
	MarshalTo([]byte) (int, error)
	Size() int
	Clone() isAuthStatus_Id
}

type AuthStatus_UserId struct {
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3,oneof" json:"user_id,omitempty"`
}
type AuthStatus_ServiceId struct {
	ServiceId *storage.ServiceIdentity `protobuf:"bytes,2,opt,name=service_id,json=serviceId,proto3,oneof" json:"service_id,omitempty"`
}

func (*AuthStatus_UserId) isAuthStatus_Id() {}
func (m *AuthStatus_UserId) Clone() isAuthStatus_Id {
	if m == nil {
		return nil
	}
	cloned := new(AuthStatus_UserId)
	*cloned = *m

	return cloned
}
func (*AuthStatus_ServiceId) isAuthStatus_Id() {}
func (m *AuthStatus_ServiceId) Clone() isAuthStatus_Id {
	if m == nil {
		return nil
	}
	cloned := new(AuthStatus_ServiceId)
	*cloned = *m

	cloned.ServiceId = m.ServiceId.Clone()
	return cloned
}

func (m *AuthStatus) GetId() isAuthStatus_Id {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *AuthStatus) GetUserId() string {
	if x, ok := m.GetId().(*AuthStatus_UserId); ok {
		return x.UserId
	}
	return ""
}

func (m *AuthStatus) GetServiceId() *storage.ServiceIdentity {
	if x, ok := m.GetId().(*AuthStatus_ServiceId); ok {
		return x.ServiceId
	}
	return nil
}

func (m *AuthStatus) GetExpires() *types.Timestamp {
	if m != nil {
		return m.Expires
	}
	return nil
}

func (m *AuthStatus) GetRefreshUrl() string {
	if m != nil {
		return m.RefreshUrl
	}
	return ""
}

func (m *AuthStatus) GetAuthProvider() *storage.AuthProvider {
	if m != nil {
		return m.AuthProvider
	}
	return nil
}

func (m *AuthStatus) GetUserInfo() *storage.UserInfo {
	if m != nil {
		return m.UserInfo
	}
	return nil
}

func (m *AuthStatus) GetUserAttributes() []*UserAttribute {
	if m != nil {
		return m.UserAttributes
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*AuthStatus) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*AuthStatus_UserId)(nil),
		(*AuthStatus_ServiceId)(nil),
	}
}

func (m *AuthStatus) MessageClone() proto.Message {
	return m.Clone()
}
func (m *AuthStatus) Clone() *AuthStatus {
	if m == nil {
		return nil
	}
	cloned := new(AuthStatus)
	*cloned = *m

	if m.Id != nil {
		cloned.Id = m.Id.Clone()
	}
	cloned.Expires = m.Expires.Clone()
	cloned.AuthProvider = m.AuthProvider.Clone()
	cloned.UserInfo = m.UserInfo.Clone()
	if m.UserAttributes != nil {
		cloned.UserAttributes = make([]*UserAttribute, len(m.UserAttributes))
		for idx, v := range m.UserAttributes {
			cloned.UserAttributes[idx] = v.Clone()
		}
	}
	return cloned
}

func init() {
	proto.RegisterType((*UserAttribute)(nil), "v1.UserAttribute")
	proto.RegisterType((*AuthStatus)(nil), "v1.AuthStatus")
}

func init() { proto.RegisterFile("api/v1/auth_service.proto", fileDescriptor_70ce5d1cdb6bc92a) }

var fileDescriptor_70ce5d1cdb6bc92a = []byte{
	// 474 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x92, 0xcf, 0x6e, 0xd3, 0x4e,
	0x10, 0xc7, 0x63, 0xa7, 0xbf, 0xe4, 0xe7, 0x09, 0x69, 0xe9, 0x4a, 0xc0, 0x36, 0x20, 0x37, 0xca,
	0x29, 0xa7, 0xb5, 0x5c, 0xb8, 0xb4, 0xb7, 0x16, 0x21, 0x9a, 0x1b, 0x72, 0xa9, 0x84, 0xb8, 0x44,
	0x9b, 0x7a, 0x93, 0xac, 0x9a, 0x78, 0xad, 0xfd, 0x63, 0xb5, 0x57, 0x5e, 0x81, 0x0b, 0x8f, 0xc4,
	0x11, 0x89, 0x17, 0x40, 0x01, 0x89, 0xd7, 0x40, 0x5e, 0xef, 0xa6, 0xe9, 0x6d, 0x66, 0xbe, 0xf3,
	0x9d, 0x9d, 0xf9, 0x68, 0xe1, 0x88, 0x96, 0x3c, 0xa9, 0xd2, 0x84, 0x1a, 0xbd, 0x9c, 0x2a, 0x26,
	0x2b, 0x7e, 0xc3, 0x48, 0x29, 0x85, 0x16, 0x28, 0xac, 0xd2, 0xc1, 0xab, 0x85, 0x10, 0x8b, 0x15,
	0x4b, 0xea, 0x2e, 0x5a, 0x14, 0x42, 0x53, 0xcd, 0x45, 0xa1, 0x9a, 0x8e, 0xc1, 0xb1, 0x53, 0x6d,
	0x36, 0x33, 0xf3, 0x44, 0xf3, 0x35, 0x53, 0x9a, 0xae, 0x4b, 0xd7, 0x80, 0xdc, 0x74, 0xb6, 0x2e,
	0xf5, 0xbd, 0xab, 0xbd, 0x54, 0x5a, 0x48, 0xba, 0x60, 0xcd, 0x93, 0xa5, 0x14, 0x15, 0xcf, 0x99,
	0x74, 0x62, 0xec, 0x45, 0xb7, 0xca, 0x94, 0xe7, 0xac, 0xd0, 0x7c, 0x6b, 0x46, 0x5e, 0x37, 0xca,
	0x7b, 0x46, 0xa7, 0xd0, 0xbf, 0x56, 0x4c, 0x9e, 0x6b, 0x2d, 0xf9, 0xcc, 0x68, 0x86, 0x9e, 0x42,
	0xfb, 0x96, 0xdd, 0xe3, 0x60, 0x18, 0x8c, 0xa3, 0xac, 0x0e, 0xd1, 0x73, 0xe8, 0x54, 0x74, 0x65,
	0x98, 0xc2, 0xe1, 0xb0, 0x3d, 0x8e, 0x32, 0x97, 0x8d, 0xfe, 0x86, 0x00, 0xe7, 0x46, 0x2f, 0xaf,
	0x34, 0xd5, 0x46, 0xa1, 0x23, 0xe8, 0xd6, 0x73, 0xa7, 0x3c, 0x6f, 0xcc, 0x97, 0xad, 0xac, 0x53,
	0x17, 0x26, 0x39, 0x3a, 0x05, 0x78, 0x58, 0x09, 0x87, 0xc3, 0x60, 0xdc, 0x3b, 0xc1, 0xc4, 0x6d,
	0x43, 0xae, 0x1a, 0x69, 0xe2, 0x96, 0xbd, 0x6c, 0x65, 0x91, 0xf2, 0x25, 0xf4, 0x06, 0xba, 0xec,
	0xae, 0xe4, 0x92, 0x29, 0xdc, 0xb6, 0xbe, 0x01, 0x69, 0xb8, 0x11, 0xcf, 0x8d, 0x7c, 0xf4, 0xdc,
	0x32, 0xdf, 0x8a, 0x8e, 0xa1, 0x27, 0xd9, 0x5c, 0x32, 0xb5, 0x9c, 0x1a, 0xb9, 0xc2, 0x7b, 0xf6,
	0x18, 0x70, 0xa5, 0x6b, 0xb9, 0x42, 0x67, 0xd0, 0x7f, 0x44, 0x10, 0xff, 0x67, 0x87, 0x3f, 0xdb,
	0x2e, 0x55, 0x1f, 0xf6, 0xc1, 0x89, 0xd9, 0x13, 0xba, 0x93, 0x21, 0x02, 0x51, 0x73, 0x68, 0x31,
	0x17, 0xb8, 0x63, 0x7d, 0x87, 0x5b, 0x5f, 0x0d, 0x73, 0x52, 0xcc, 0x45, 0xf6, 0xbf, 0x71, 0x11,
	0x3a, 0x83, 0x03, 0xdb, 0x4f, 0x3d, 0x63, 0x85, 0xbb, 0xc3, 0xb6, 0x75, 0x55, 0x29, 0x79, 0x44,
	0x3f, 0xdb, 0x37, 0xbb, 0xa9, 0xba, 0xd8, 0x83, 0x90, 0xe7, 0x27, 0x19, 0xf4, 0x2c, 0xe8, 0x86,
	0x0a, 0x7a, 0x0b, 0xfd, 0xf7, 0x4c, 0xef, 0xa0, 0x8f, 0xea, 0x41, 0xef, 0xea, 0x6f, 0x32, 0xd8,
	0xaf, 0xc3, 0x07, 0x69, 0xf4, 0xe2, 0xcb, 0xcf, 0x3f, 0x5f, 0xc3, 0x43, 0x74, 0xe0, 0xff, 0x69,
	0xa2, 0xac, 0x70, 0x41, 0xbe, 0x6f, 0xe2, 0xe0, 0xc7, 0x26, 0x0e, 0x7e, 0x6d, 0xe2, 0xe0, 0xdb,
	0xef, 0xb8, 0x05, 0x98, 0x0b, 0xa2, 0x34, 0xbd, 0xb9, 0x95, 0xe2, 0xae, 0xa1, 0x4b, 0x68, 0xc9,
	0x49, 0x95, 0x7e, 0x0e, 0xab, 0xf4, 0x53, 0x6b, 0xd6, 0xb1, 0xb5, 0xd7, 0xff, 0x02, 0x00, 0x00,
	0xff, 0xff, 0x76, 0xa5, 0x08, 0xcf, 0xf6, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// AuthServiceClient is the client API for AuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConnInterface.NewStream.
type AuthServiceClient interface {
	GetAuthStatus(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AuthStatus, error)
}

type authServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServiceClient(cc grpc.ClientConnInterface) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) GetAuthStatus(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AuthStatus, error) {
	out := new(AuthStatus)
	err := c.cc.Invoke(ctx, "/v1.AuthService/GetAuthStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServiceServer is the server API for AuthService service.
type AuthServiceServer interface {
	GetAuthStatus(context.Context, *Empty) (*AuthStatus, error)
}

// UnimplementedAuthServiceServer can be embedded to have forward compatible implementations.
type UnimplementedAuthServiceServer struct {
}

func (*UnimplementedAuthServiceServer) GetAuthStatus(ctx context.Context, req *Empty) (*AuthStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAuthStatus not implemented")
}

func RegisterAuthServiceServer(s *grpc.Server, srv AuthServiceServer) {
	s.RegisterService(&_AuthService_serviceDesc, srv)
}

func _AuthService_GetAuthStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).GetAuthStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.AuthService/GetAuthStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).GetAuthStatus(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _AuthService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "v1.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAuthStatus",
			Handler:    _AuthService_GetAuthStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/auth_service.proto",
}

func (m *UserAttribute) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *UserAttribute) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *UserAttribute) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Values) > 0 {
		for iNdEx := len(m.Values) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Values[iNdEx])
			copy(dAtA[i:], m.Values[iNdEx])
			i = encodeVarintAuthService(dAtA, i, uint64(len(m.Values[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.Key) > 0 {
		i -= len(m.Key)
		copy(dAtA[i:], m.Key)
		i = encodeVarintAuthService(dAtA, i, uint64(len(m.Key)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *AuthStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AuthStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AuthStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.UserAttributes) > 0 {
		for iNdEx := len(m.UserAttributes) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.UserAttributes[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintAuthService(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x3a
		}
	}
	if m.UserInfo != nil {
		{
			size, err := m.UserInfo.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAuthService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	if m.AuthProvider != nil {
		{
			size, err := m.AuthProvider.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAuthService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if len(m.RefreshUrl) > 0 {
		i -= len(m.RefreshUrl)
		copy(dAtA[i:], m.RefreshUrl)
		i = encodeVarintAuthService(dAtA, i, uint64(len(m.RefreshUrl)))
		i--
		dAtA[i] = 0x22
	}
	if m.Expires != nil {
		{
			size, err := m.Expires.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAuthService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.Id != nil {
		{
			size := m.Id.Size()
			i -= size
			if _, err := m.Id.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	return len(dAtA) - i, nil
}

func (m *AuthStatus_UserId) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AuthStatus_UserId) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i -= len(m.UserId)
	copy(dAtA[i:], m.UserId)
	i = encodeVarintAuthService(dAtA, i, uint64(len(m.UserId)))
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}
func (m *AuthStatus_ServiceId) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AuthStatus_ServiceId) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.ServiceId != nil {
		{
			size, err := m.ServiceId.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAuthService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	return len(dAtA) - i, nil
}
func encodeVarintAuthService(dAtA []byte, offset int, v uint64) int {
	offset -= sovAuthService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *UserAttribute) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Key)
	if l > 0 {
		n += 1 + l + sovAuthService(uint64(l))
	}
	if len(m.Values) > 0 {
		for _, s := range m.Values {
			l = len(s)
			n += 1 + l + sovAuthService(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *AuthStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != nil {
		n += m.Id.Size()
	}
	if m.Expires != nil {
		l = m.Expires.Size()
		n += 1 + l + sovAuthService(uint64(l))
	}
	l = len(m.RefreshUrl)
	if l > 0 {
		n += 1 + l + sovAuthService(uint64(l))
	}
	if m.AuthProvider != nil {
		l = m.AuthProvider.Size()
		n += 1 + l + sovAuthService(uint64(l))
	}
	if m.UserInfo != nil {
		l = m.UserInfo.Size()
		n += 1 + l + sovAuthService(uint64(l))
	}
	if len(m.UserAttributes) > 0 {
		for _, e := range m.UserAttributes {
			l = e.Size()
			n += 1 + l + sovAuthService(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *AuthStatus_UserId) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.UserId)
	n += 1 + l + sovAuthService(uint64(l))
	return n
}
func (m *AuthStatus_ServiceId) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ServiceId != nil {
		l = m.ServiceId.Size()
		n += 1 + l + sovAuthService(uint64(l))
	}
	return n
}

func sovAuthService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAuthService(x uint64) (n int) {
	return sovAuthService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *UserAttribute) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAuthService
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
			return fmt.Errorf("proto: UserAttribute: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: UserAttribute: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Key = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Values", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Values = append(m.Values, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAuthService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAuthService
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
func (m *AuthStatus) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAuthService
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
			return fmt.Errorf("proto: AuthStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AuthStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = &AuthStatus_UserId{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ServiceId", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &storage.ServiceIdentity{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Id = &AuthStatus_ServiceId{v}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Expires", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Expires == nil {
				m.Expires = &types.Timestamp{}
			}
			if err := m.Expires.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RefreshUrl", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RefreshUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AuthProvider", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AuthProvider == nil {
				m.AuthProvider = &storage.AuthProvider{}
			}
			if err := m.AuthProvider.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserInfo", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.UserInfo == nil {
				m.UserInfo = &storage.UserInfo{}
			}
			if err := m.UserInfo.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserAttributes", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAuthService
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
				return ErrInvalidLengthAuthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAuthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.UserAttributes = append(m.UserAttributes, &UserAttribute{})
			if err := m.UserAttributes[len(m.UserAttributes)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAuthService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAuthService
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
func skipAuthService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAuthService
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
					return 0, ErrIntOverflowAuthService
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
					return 0, ErrIntOverflowAuthService
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
				return 0, ErrInvalidLengthAuthService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAuthService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAuthService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAuthService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAuthService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAuthService = fmt.Errorf("proto: unexpected end of group")
)
