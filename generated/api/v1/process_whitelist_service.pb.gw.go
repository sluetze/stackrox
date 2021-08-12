// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: api/v1/process_whitelist_service.proto

/*
Package v1 is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package v1

import (
	"context"
	"io"
	"net/http"

	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
)

// Suppress "imported and not used" errors
var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray
var _ = descriptor.ForMessage

var (
	filter_ProcessWhitelistService_GetProcessWhitelist_0 = &utilities.DoubleArray{Encoding: map[string]int{}, Base: []int(nil), Check: []int(nil)}
)

func request_ProcessWhitelistService_GetProcessWhitelist_0(ctx context.Context, marshaler runtime.Marshaler, client ProcessWhitelistServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetProcessWhitelistRequest
	var metadata runtime.ServerMetadata

	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_ProcessWhitelistService_GetProcessWhitelist_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.GetProcessWhitelist(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_ProcessWhitelistService_GetProcessWhitelist_0(ctx context.Context, marshaler runtime.Marshaler, server ProcessWhitelistServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetProcessWhitelistRequest
	var metadata runtime.ServerMetadata

	if err := runtime.PopulateQueryParameters(&protoReq, req.URL.Query(), filter_ProcessWhitelistService_GetProcessWhitelist_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.GetProcessWhitelist(ctx, &protoReq)
	return msg, metadata, err

}

func request_ProcessWhitelistService_UpdateProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, client ProcessWhitelistServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq UpdateProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.UpdateProcessWhitelists(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_ProcessWhitelistService_UpdateProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, server ProcessWhitelistServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq UpdateProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.UpdateProcessWhitelists(ctx, &protoReq)
	return msg, metadata, err

}

func request_ProcessWhitelistService_LockProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, client ProcessWhitelistServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq LockProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.LockProcessWhitelists(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_ProcessWhitelistService_LockProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, server ProcessWhitelistServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq LockProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.LockProcessWhitelists(ctx, &protoReq)
	return msg, metadata, err

}

var (
	filter_ProcessWhitelistService_DeleteProcessWhitelists_0 = &utilities.DoubleArray{Encoding: map[string]int{}, Base: []int(nil), Check: []int(nil)}
)

func request_ProcessWhitelistService_DeleteProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, client ProcessWhitelistServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeleteProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_ProcessWhitelistService_DeleteProcessWhitelists_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.DeleteProcessWhitelists(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_ProcessWhitelistService_DeleteProcessWhitelists_0(ctx context.Context, marshaler runtime.Marshaler, server ProcessWhitelistServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeleteProcessWhitelistsRequest
	var metadata runtime.ServerMetadata

	if err := runtime.PopulateQueryParameters(&protoReq, req.URL.Query(), filter_ProcessWhitelistService_DeleteProcessWhitelists_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.DeleteProcessWhitelists(ctx, &protoReq)
	return msg, metadata, err

}

// RegisterProcessWhitelistServiceHandlerServer registers the http handlers for service ProcessWhitelistService to "mux".
// UnaryRPC     :call ProcessWhitelistServiceServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
func RegisterProcessWhitelistServiceHandlerServer(ctx context.Context, mux *runtime.ServeMux, server ProcessWhitelistServiceServer) error {

	mux.Handle("GET", pattern_ProcessWhitelistService_GetProcessWhitelist_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_ProcessWhitelistService_GetProcessWhitelist_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_GetProcessWhitelist_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PUT", pattern_ProcessWhitelistService_UpdateProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_ProcessWhitelistService_UpdateProcessWhitelists_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_UpdateProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PUT", pattern_ProcessWhitelistService_LockProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_ProcessWhitelistService_LockProcessWhitelists_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_LockProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_ProcessWhitelistService_DeleteProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_ProcessWhitelistService_DeleteProcessWhitelists_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_DeleteProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

// RegisterProcessWhitelistServiceHandlerFromEndpoint is same as RegisterProcessWhitelistServiceHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterProcessWhitelistServiceHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterProcessWhitelistServiceHandler(ctx, mux, conn)
}

// RegisterProcessWhitelistServiceHandler registers the http handlers for service ProcessWhitelistService to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterProcessWhitelistServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterProcessWhitelistServiceHandlerClient(ctx, mux, NewProcessWhitelistServiceClient(conn))
}

// RegisterProcessWhitelistServiceHandlerClient registers the http handlers for service ProcessWhitelistService
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "ProcessWhitelistServiceClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "ProcessWhitelistServiceClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "ProcessWhitelistServiceClient" to call the correct interceptors.
func RegisterProcessWhitelistServiceHandlerClient(ctx context.Context, mux *runtime.ServeMux, client ProcessWhitelistServiceClient) error {

	mux.Handle("GET", pattern_ProcessWhitelistService_GetProcessWhitelist_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_ProcessWhitelistService_GetProcessWhitelist_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_GetProcessWhitelist_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PUT", pattern_ProcessWhitelistService_UpdateProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_ProcessWhitelistService_UpdateProcessWhitelists_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_UpdateProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PUT", pattern_ProcessWhitelistService_LockProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_ProcessWhitelistService_LockProcessWhitelists_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_LockProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_ProcessWhitelistService_DeleteProcessWhitelists_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_ProcessWhitelistService_DeleteProcessWhitelists_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_ProcessWhitelistService_DeleteProcessWhitelists_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_ProcessWhitelistService_GetProcessWhitelist_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v1", "processwhitelists", "key"}, "", runtime.AssumeColonVerbOpt(false)))

	pattern_ProcessWhitelistService_UpdateProcessWhitelists_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"v1", "processwhitelists"}, "", runtime.AssumeColonVerbOpt(false)))

	pattern_ProcessWhitelistService_LockProcessWhitelists_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v1", "processwhitelists", "lock"}, "", runtime.AssumeColonVerbOpt(false)))

	pattern_ProcessWhitelistService_DeleteProcessWhitelists_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"v1", "processwhitelists"}, "", runtime.AssumeColonVerbOpt(false)))
)

var (
	forward_ProcessWhitelistService_GetProcessWhitelist_0 = runtime.ForwardResponseMessage

	forward_ProcessWhitelistService_UpdateProcessWhitelists_0 = runtime.ForwardResponseMessage

	forward_ProcessWhitelistService_LockProcessWhitelists_0 = runtime.ForwardResponseMessage

	forward_ProcessWhitelistService_DeleteProcessWhitelists_0 = runtime.ForwardResponseMessage
)
