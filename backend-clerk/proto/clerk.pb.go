// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.4
// 	protoc        v5.29.3
// source: clerk.proto

package clerk

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EmptyRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EmptyRequest) Reset() {
	*x = EmptyRequest{}
	mi := &file_clerk_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EmptyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EmptyRequest) ProtoMessage() {}

func (x *EmptyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_clerk_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EmptyRequest.ProtoReflect.Descriptor instead.
func (*EmptyRequest) Descriptor() ([]byte, []int) {
	return file_clerk_proto_rawDescGZIP(), []int{0}
}

type Clerk struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            int32                  `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Clerk) Reset() {
	*x = Clerk{}
	mi := &file_clerk_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Clerk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Clerk) ProtoMessage() {}

func (x *Clerk) ProtoReflect() protoreflect.Message {
	mi := &file_clerk_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Clerk.ProtoReflect.Descriptor instead.
func (*Clerk) Descriptor() ([]byte, []int) {
	return file_clerk_proto_rawDescGZIP(), []int{1}
}

func (x *Clerk) GetID() int32 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *Clerk) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type ClaimResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Message       string                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Roles         []string               `protobuf:"bytes,2,rep,name=roles,proto3" json:"roles,omitempty"`
	StoreIDs      []string               `protobuf:"bytes,3,rep,name=storeIDs,proto3" json:"storeIDs,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ClaimResponse) Reset() {
	*x = ClaimResponse{}
	mi := &file_clerk_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClaimResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClaimResponse) ProtoMessage() {}

func (x *ClaimResponse) ProtoReflect() protoreflect.Message {
	mi := &file_clerk_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClaimResponse.ProtoReflect.Descriptor instead.
func (*ClaimResponse) Descriptor() ([]byte, []int) {
	return file_clerk_proto_rawDescGZIP(), []int{2}
}

func (x *ClaimResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *ClaimResponse) GetRoles() []string {
	if x != nil {
		return x.Roles
	}
	return nil
}

func (x *ClaimResponse) GetStoreIDs() []string {
	if x != nil {
		return x.StoreIDs
	}
	return nil
}

type ClientResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            int32                  `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ClientResponse) Reset() {
	*x = ClientResponse{}
	mi := &file_clerk_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientResponse) ProtoMessage() {}

func (x *ClientResponse) ProtoReflect() protoreflect.Message {
	mi := &file_clerk_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientResponse.ProtoReflect.Descriptor instead.
func (*ClientResponse) Descriptor() ([]byte, []int) {
	return file_clerk_proto_rawDescGZIP(), []int{3}
}

func (x *ClientResponse) GetID() int32 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *ClientResponse) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type AdminResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            int32                  `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdminResponse) Reset() {
	*x = AdminResponse{}
	mi := &file_clerk_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdminResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdminResponse) ProtoMessage() {}

func (x *AdminResponse) ProtoReflect() protoreflect.Message {
	mi := &file_clerk_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdminResponse.ProtoReflect.Descriptor instead.
func (*AdminResponse) Descriptor() ([]byte, []int) {
	return file_clerk_proto_rawDescGZIP(), []int{4}
}

func (x *AdminResponse) GetID() int32 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *AdminResponse) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_clerk_proto protoreflect.FileDescriptor

var file_clerk_proto_rawDesc = string([]byte{
	0x0a, 0x0b, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x63,
	0x6c, 0x65, 0x72, 0x6b, 0x22, 0x0e, 0x0a, 0x0c, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x22, 0x2b, 0x0a, 0x05, 0x43, 0x6c, 0x65, 0x72, 0x6b, 0x12, 0x0e, 0x0a,
	0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x02, 0x49, 0x44, 0x12, 0x12, 0x0a,
	0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d,
	0x65, 0x22, 0x5b, 0x0a, 0x0d, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f, 0x6c,
	0x65, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x49, 0x44, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x49, 0x44, 0x73, 0x22, 0x34,
	0x0a, 0x0e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x0e, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x02, 0x49, 0x44,
	0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x4e, 0x61, 0x6d, 0x65, 0x22, 0x33, 0x0a, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x02, 0x49, 0x44, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x32, 0x80, 0x02, 0x0a, 0x0c, 0x43, 0x6c,
	0x65, 0x72, 0x6b, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x30, 0x0a, 0x09, 0x47, 0x65,
	0x74, 0x43, 0x6c, 0x65, 0x72, 0x6b, 0x73, 0x12, 0x13, 0x2e, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0c, 0x2e, 0x63,
	0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x43, 0x6c, 0x65, 0x72, 0x6b, 0x30, 0x01, 0x12, 0x36, 0x0a, 0x09,
	0x47, 0x65, 0x74, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x12, 0x13, 0x2e, 0x63, 0x6c, 0x65, 0x72,
	0x6b, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x14,
	0x2e, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x46, 0x72, 0x6f, 0x6d, 0x43, 0x6c, 0x65, 0x72, 0x6b, 0x12, 0x13, 0x2e, 0x63, 0x6c,
	0x65, 0x72, 0x6b, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x15, 0x2e, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x41, 0x0a, 0x12, 0x47, 0x65, 0x74,
	0x41, 0x64, 0x6d, 0x69, 0x6e, 0x73, 0x46, 0x72, 0x6f, 0x6d, 0x43, 0x6c, 0x65, 0x72, 0x6b, 0x12,
	0x13, 0x2e, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x14, 0x2e, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x2e, 0x41, 0x64, 0x6d,
	0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x42, 0x0f, 0x5a, 0x0d,
	0x2e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x63, 0x6c, 0x65, 0x72, 0x6b, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_clerk_proto_rawDescOnce sync.Once
	file_clerk_proto_rawDescData []byte
)

func file_clerk_proto_rawDescGZIP() []byte {
	file_clerk_proto_rawDescOnce.Do(func() {
		file_clerk_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_clerk_proto_rawDesc), len(file_clerk_proto_rawDesc)))
	})
	return file_clerk_proto_rawDescData
}

var file_clerk_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_clerk_proto_goTypes = []any{
	(*EmptyRequest)(nil),   // 0: clerk.EmptyRequest
	(*Clerk)(nil),          // 1: clerk.Clerk
	(*ClaimResponse)(nil),  // 2: clerk.ClaimResponse
	(*ClientResponse)(nil), // 3: clerk.ClientResponse
	(*AdminResponse)(nil),  // 4: clerk.AdminResponse
}
var file_clerk_proto_depIdxs = []int32{
	0, // 0: clerk.ClerkService.GetClerks:input_type -> clerk.EmptyRequest
	0, // 1: clerk.ClerkService.GetClaims:input_type -> clerk.EmptyRequest
	0, // 2: clerk.ClerkService.GetClientsFromClerk:input_type -> clerk.EmptyRequest
	0, // 3: clerk.ClerkService.GetAdminsFromClerk:input_type -> clerk.EmptyRequest
	1, // 4: clerk.ClerkService.GetClerks:output_type -> clerk.Clerk
	2, // 5: clerk.ClerkService.GetClaims:output_type -> clerk.ClaimResponse
	3, // 6: clerk.ClerkService.GetClientsFromClerk:output_type -> clerk.ClientResponse
	4, // 7: clerk.ClerkService.GetAdminsFromClerk:output_type -> clerk.AdminResponse
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_clerk_proto_init() }
func file_clerk_proto_init() {
	if File_clerk_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_clerk_proto_rawDesc), len(file_clerk_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_clerk_proto_goTypes,
		DependencyIndexes: file_clerk_proto_depIdxs,
		MessageInfos:      file_clerk_proto_msgTypes,
	}.Build()
	File_clerk_proto = out.File
	file_clerk_proto_goTypes = nil
	file_clerk_proto_depIdxs = nil
}
