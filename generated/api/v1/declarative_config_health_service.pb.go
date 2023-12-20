// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/v1/declarative_config_health_service.proto

package v1

import (
	context "context"
	fmt "fmt"
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

type GetDeclarativeConfigHealthsResponse struct {
	Healths              []*storage.DeclarativeConfigHealth `protobuf:"bytes,1,rep,name=healths,proto3" json:"healths,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *GetDeclarativeConfigHealthsResponse) Reset()         { *m = GetDeclarativeConfigHealthsResponse{} }
func (m *GetDeclarativeConfigHealthsResponse) String() string { return proto.CompactTextString(m) }
func (*GetDeclarativeConfigHealthsResponse) ProtoMessage()    {}
func (*GetDeclarativeConfigHealthsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_bcfabb16bd33cd5d, []int{0}
}
func (m *GetDeclarativeConfigHealthsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GetDeclarativeConfigHealthsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GetDeclarativeConfigHealthsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GetDeclarativeConfigHealthsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetDeclarativeConfigHealthsResponse.Merge(m, src)
}
func (m *GetDeclarativeConfigHealthsResponse) XXX_Size() int {
	return m.Size()
}
func (m *GetDeclarativeConfigHealthsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetDeclarativeConfigHealthsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetDeclarativeConfigHealthsResponse proto.InternalMessageInfo

func (m *GetDeclarativeConfigHealthsResponse) GetHealths() []*storage.DeclarativeConfigHealth {
	if m != nil {
		return m.Healths
	}
	return nil
}

func (m *GetDeclarativeConfigHealthsResponse) MessageClone() proto.Message {
	return m.Clone()
}
func (m *GetDeclarativeConfigHealthsResponse) Clone() *GetDeclarativeConfigHealthsResponse {
	if m == nil {
		return nil
	}
	cloned := new(GetDeclarativeConfigHealthsResponse)
	*cloned = *m

	if m.Healths != nil {
		cloned.Healths = make([]*storage.DeclarativeConfigHealth, len(m.Healths))
		for idx, v := range m.Healths {
			cloned.Healths[idx] = v.Clone()
		}
	}
	return cloned
}

func init() {
	proto.RegisterType((*GetDeclarativeConfigHealthsResponse)(nil), "v1.GetDeclarativeConfigHealthsResponse")
}

func init() {
	proto.RegisterFile("api/v1/declarative_config_health_service.proto", fileDescriptor_bcfabb16bd33cd5d)
}

var fileDescriptor_bcfabb16bd33cd5d = []byte{
	// 275 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4b, 0x2c, 0xc8, 0xd4,
	0x2f, 0x33, 0xd4, 0x4f, 0x49, 0x4d, 0xce, 0x49, 0x2c, 0x4a, 0x2c, 0xc9, 0x2c, 0x4b, 0x8d, 0x4f,
	0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0x8f, 0xcf, 0x48, 0x4d, 0xcc, 0x29, 0xc9, 0x88, 0x2f, 0x4e, 0x2d,
	0x2a, 0xcb, 0x4c, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x2a, 0x33, 0x94, 0x12,
	0x82, 0xea, 0x49, 0xcd, 0x2d, 0x28, 0xa9, 0x84, 0x88, 0x4b, 0xc9, 0xa4, 0xe7, 0xe7, 0xa7, 0xe7,
	0xa4, 0xea, 0x83, 0xa4, 0x12, 0xf3, 0xf2, 0xf2, 0x4b, 0x12, 0x4b, 0x32, 0xf3, 0xf3, 0x8a, 0xa1,
	0xb2, 0xea, 0xc5, 0x25, 0xf9, 0x45, 0x89, 0xe9, 0xa9, 0xb8, 0xad, 0x81, 0x28, 0x54, 0x4a, 0xe4,
	0x52, 0x76, 0x4f, 0x2d, 0x71, 0x41, 0xa8, 0x72, 0x06, 0x2b, 0xf2, 0x00, 0xab, 0x29, 0x0e, 0x4a,
	0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x15, 0xb2, 0xe2, 0x62, 0x87, 0x68, 0x2b, 0x96, 0x60, 0x54,
	0x60, 0xd6, 0xe0, 0x36, 0x52, 0xd0, 0x83, 0xda, 0xa0, 0x87, 0x43, 0x6f, 0x10, 0x4c, 0x83, 0xd1,
	0x2c, 0x46, 0x2e, 0x39, 0x1c, 0x8a, 0x82, 0x21, 0x5e, 0x15, 0xaa, 0xe0, 0x92, 0xc6, 0xe3, 0x0a,
	0x21, 0x4e, 0xbd, 0x32, 0x43, 0x3d, 0x57, 0x90, 0xe7, 0xa5, 0xd4, 0x41, 0x4c, 0x22, 0x5c, 0xac,
	0xa4, 0xda, 0x74, 0xf9, 0xc9, 0x64, 0x26, 0x79, 0x21, 0x59, 0xb4, 0xc0, 0xd6, 0x85, 0x84, 0x82,
	0x3e, 0xc4, 0x75, 0x4e, 0x7a, 0x27, 0x1e, 0xc9, 0x31, 0x5e, 0x78, 0x24, 0xc7, 0xf8, 0xe0, 0x91,
	0x1c, 0xe3, 0x8c, 0xc7, 0x72, 0x0c, 0x5c, 0x12, 0x99, 0xf9, 0x7a, 0xc5, 0x25, 0x89, 0xc9, 0xd9,
	0x45, 0xf9, 0x15, 0x90, 0x40, 0x02, 0x45, 0x99, 0x5e, 0x99, 0x61, 0x14, 0x53, 0x99, 0x61, 0x04,
	0x63, 0x12, 0x1b, 0x58, 0xcc, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0x73, 0xd7, 0x32, 0x42, 0xc9,
	0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// DeclarativeConfigHealthServiceClient is the client API for DeclarativeConfigHealthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConnInterface.NewStream.
type DeclarativeConfigHealthServiceClient interface {
	GetDeclarativeConfigHealths(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*GetDeclarativeConfigHealthsResponse, error)
}

type declarativeConfigHealthServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDeclarativeConfigHealthServiceClient(cc grpc.ClientConnInterface) DeclarativeConfigHealthServiceClient {
	return &declarativeConfigHealthServiceClient{cc}
}

func (c *declarativeConfigHealthServiceClient) GetDeclarativeConfigHealths(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*GetDeclarativeConfigHealthsResponse, error) {
	out := new(GetDeclarativeConfigHealthsResponse)
	err := c.cc.Invoke(ctx, "/v1.DeclarativeConfigHealthService/GetDeclarativeConfigHealths", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeclarativeConfigHealthServiceServer is the server API for DeclarativeConfigHealthService service.
type DeclarativeConfigHealthServiceServer interface {
	GetDeclarativeConfigHealths(context.Context, *Empty) (*GetDeclarativeConfigHealthsResponse, error)
}

// UnimplementedDeclarativeConfigHealthServiceServer can be embedded to have forward compatible implementations.
type UnimplementedDeclarativeConfigHealthServiceServer struct {
}

func (*UnimplementedDeclarativeConfigHealthServiceServer) GetDeclarativeConfigHealths(ctx context.Context, req *Empty) (*GetDeclarativeConfigHealthsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDeclarativeConfigHealths not implemented")
}

func RegisterDeclarativeConfigHealthServiceServer(s *grpc.Server, srv DeclarativeConfigHealthServiceServer) {
	s.RegisterService(&_DeclarativeConfigHealthService_serviceDesc, srv)
}

func _DeclarativeConfigHealthService_GetDeclarativeConfigHealths_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeclarativeConfigHealthServiceServer).GetDeclarativeConfigHealths(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1.DeclarativeConfigHealthService/GetDeclarativeConfigHealths",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeclarativeConfigHealthServiceServer).GetDeclarativeConfigHealths(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _DeclarativeConfigHealthService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "v1.DeclarativeConfigHealthService",
	HandlerType: (*DeclarativeConfigHealthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetDeclarativeConfigHealths",
			Handler:    _DeclarativeConfigHealthService_GetDeclarativeConfigHealths_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/declarative_config_health_service.proto",
}

func (m *GetDeclarativeConfigHealthsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetDeclarativeConfigHealthsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GetDeclarativeConfigHealthsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Healths) > 0 {
		for iNdEx := len(m.Healths) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Healths[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintDeclarativeConfigHealthService(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintDeclarativeConfigHealthService(dAtA []byte, offset int, v uint64) int {
	offset -= sovDeclarativeConfigHealthService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GetDeclarativeConfigHealthsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Healths) > 0 {
		for _, e := range m.Healths {
			l = e.Size()
			n += 1 + l + sovDeclarativeConfigHealthService(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovDeclarativeConfigHealthService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozDeclarativeConfigHealthService(x uint64) (n int) {
	return sovDeclarativeConfigHealthService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *GetDeclarativeConfigHealthsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDeclarativeConfigHealthService
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
			return fmt.Errorf("proto: GetDeclarativeConfigHealthsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetDeclarativeConfigHealthsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Healths", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealthService
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
				return ErrInvalidLengthDeclarativeConfigHealthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Healths = append(m.Healths, &storage.DeclarativeConfigHealth{})
			if err := m.Healths[len(m.Healths)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDeclarativeConfigHealthService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthDeclarativeConfigHealthService
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
func skipDeclarativeConfigHealthService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDeclarativeConfigHealthService
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
					return 0, ErrIntOverflowDeclarativeConfigHealthService
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
					return 0, ErrIntOverflowDeclarativeConfigHealthService
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
				return 0, ErrInvalidLengthDeclarativeConfigHealthService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupDeclarativeConfigHealthService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthDeclarativeConfigHealthService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthDeclarativeConfigHealthService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDeclarativeConfigHealthService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupDeclarativeConfigHealthService = fmt.Errorf("proto: unexpected end of group")
)
