// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: internalapi/sensor/collector.proto

package sensor

import (
	fmt "fmt"
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

// A request message sent by collector to register with Sensor. Typically the first message in any streams.
type CollectorRegisterRequest struct {
	// The hostname on which collector is running.
	Hostname string `protobuf:"bytes,1,opt,name=hostname,proto3" json:"hostname,omitempty"`
	// A unique identifier for an instance of collector.
	InstanceId           string   `protobuf:"bytes,2,opt,name=instance_id,json=instanceId,proto3" json:"instance_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CollectorRegisterRequest) Reset()         { *m = CollectorRegisterRequest{} }
func (m *CollectorRegisterRequest) String() string { return proto.CompactTextString(m) }
func (*CollectorRegisterRequest) ProtoMessage()    {}
func (*CollectorRegisterRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_71453edf4e1b15cc, []int{0}
}
func (m *CollectorRegisterRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CollectorRegisterRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CollectorRegisterRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CollectorRegisterRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CollectorRegisterRequest.Merge(m, src)
}
func (m *CollectorRegisterRequest) XXX_Size() int {
	return m.Size()
}
func (m *CollectorRegisterRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CollectorRegisterRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CollectorRegisterRequest proto.InternalMessageInfo

func (m *CollectorRegisterRequest) GetHostname() string {
	if m != nil {
		return m.Hostname
	}
	return ""
}

func (m *CollectorRegisterRequest) GetInstanceId() string {
	if m != nil {
		return m.InstanceId
	}
	return ""
}

func (m *CollectorRegisterRequest) MessageClone() proto.Message {
	return m.Clone()
}
func (m *CollectorRegisterRequest) Clone() *CollectorRegisterRequest {
	if m == nil {
		return nil
	}
	cloned := new(CollectorRegisterRequest)
	*cloned = *m

	return cloned
}

func init() {
	proto.RegisterType((*CollectorRegisterRequest)(nil), "sensor.CollectorRegisterRequest")
}

func init() {
	proto.RegisterFile("internalapi/sensor/collector.proto", fileDescriptor_71453edf4e1b15cc)
}

var fileDescriptor_71453edf4e1b15cc = []byte{
	// 161 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0xca, 0xcc, 0x2b, 0x49,
	0x2d, 0xca, 0x4b, 0xcc, 0x49, 0x2c, 0xc8, 0xd4, 0x2f, 0x4e, 0xcd, 0x2b, 0xce, 0x2f, 0xd2, 0x4f,
	0xce, 0xcf, 0xc9, 0x49, 0x4d, 0x2e, 0xc9, 0x2f, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62,
	0x83, 0x88, 0x2b, 0x85, 0x73, 0x49, 0x38, 0xc3, 0xa4, 0x82, 0x52, 0xd3, 0x33, 0x8b, 0x4b, 0x52,
	0x8b, 0x82, 0x52, 0x0b, 0x4b, 0x53, 0x8b, 0x4b, 0x84, 0xa4, 0xb8, 0x38, 0x32, 0xf2, 0x8b, 0x4b,
	0xf2, 0x12, 0x73, 0x53, 0x25, 0x18, 0x15, 0x18, 0x35, 0x38, 0x83, 0xe0, 0x7c, 0x21, 0x79, 0x2e,
	0xee, 0xcc, 0xbc, 0xe2, 0x92, 0xc4, 0xbc, 0xe4, 0xd4, 0xf8, 0xcc, 0x14, 0x09, 0x26, 0xb0, 0x34,
	0x17, 0x4c, 0xc8, 0x33, 0xc5, 0x49, 0xfa, 0xc4, 0x23, 0x39, 0xc6, 0x0b, 0x8f, 0xe4, 0x18, 0x1f,
	0x3c, 0x92, 0x63, 0x9c, 0xf1, 0x58, 0x8e, 0x21, 0x0a, 0x6a, 0xe5, 0x0f, 0x46, 0xc6, 0x24, 0x36,
	0xb0, 0x23, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x85, 0x07, 0xa8, 0x0b, 0xaa, 0x00, 0x00,
	0x00,
}

func (m *CollectorRegisterRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CollectorRegisterRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CollectorRegisterRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.InstanceId) > 0 {
		i -= len(m.InstanceId)
		copy(dAtA[i:], m.InstanceId)
		i = encodeVarintCollector(dAtA, i, uint64(len(m.InstanceId)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Hostname) > 0 {
		i -= len(m.Hostname)
		copy(dAtA[i:], m.Hostname)
		i = encodeVarintCollector(dAtA, i, uint64(len(m.Hostname)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintCollector(dAtA []byte, offset int, v uint64) int {
	offset -= sovCollector(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *CollectorRegisterRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Hostname)
	if l > 0 {
		n += 1 + l + sovCollector(uint64(l))
	}
	l = len(m.InstanceId)
	if l > 0 {
		n += 1 + l + sovCollector(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovCollector(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozCollector(x uint64) (n int) {
	return sovCollector(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *CollectorRegisterRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCollector
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
			return fmt.Errorf("proto: CollectorRegisterRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CollectorRegisterRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Hostname", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCollector
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
				return ErrInvalidLengthCollector
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCollector
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Hostname = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field InstanceId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCollector
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
				return ErrInvalidLengthCollector
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCollector
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.InstanceId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCollector(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCollector
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
func skipCollector(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCollector
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
					return 0, ErrIntOverflowCollector
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
					return 0, ErrIntOverflowCollector
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
				return 0, ErrInvalidLengthCollector
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupCollector
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthCollector
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthCollector        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCollector          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupCollector = fmt.Errorf("proto: unexpected end of group")
)
