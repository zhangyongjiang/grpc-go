package main

import (
  "flag"
  "net/http"

  "github.com/golang/glog"
  "golang.org/x/net/context"
  "github.com/grpc-ecosystem/grpc-gateway/runtime"
  "google.golang.org/grpc"
	
  gw "google.golang.org/grpc/examples/route_guide/routeguide"
)

var (
  echoEndpoint = flag.String("echo_endpoint", "localhost:9090", "endpoint of YourService")
)

func run() error {
  ctx := context.Background()
  ctx, cancel := context.WithCancel(ctx)
  defer cancel()



  var opts []grpc.DialOption
  if *tls {
    var sn string
    if *serverHostOverride != "" {
      sn = *serverHostOverride
    }
    var creds credentials.TransportCredentials
    if *caFile != "" {
      var err error
      creds, err = credentials.NewClientTLSFromFile(*caFile, sn)
      if err != nil {
        grpclog.Fatalf("Failed to create TLS credentials %v", err)
      }
    } else {
      creds = credentials.NewClientTLSFromCert(nil, sn)
    }
    opts = append(opts, grpc.WithTransportCredentials(creds))
  } else {
    opts = append(opts, grpc.WithInsecure())
  }


  mux := runtime.NewServeMux()
  //opts := []grpc.DialOption{grpc.WithInsecure()}
  opts := []grpc.DialOption{grpc.With}
  err := gw.RegisterRouteGuideHandlerFromEndpoint(ctx, mux, *echoEndpoint, opts)
  if err != nil {
    return err
  }

  //return http.ListenAndServe(":8080", mux)
  return http.ListenAndServeTLS(":8443", "testdata/server1.pem","testdata/server1.key",mux)
}

func main() {
  flag.Parse()
  defer glog.Flush()

  if err := run(); err != nil {
    glog.Fatal(err)
  }
}

