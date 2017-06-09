package main

import (
	"flag"
	"io"
	"math/rand"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "google.golang.org/grpc/examples/block_chain/blockchain"
	"google.golang.org/grpc/grpclog"
)

var (
	tls                = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	serverAddr         = flag.String("server_addr", "127.0.0.1:9090", "The server address in the format of host:port")
)

// printChaininfo gets the chaininfo.
func printChaininfo(client pb.BlockChainClient, em *pb.EmptyMsg) {
	grpclog.Printf("Getting chaininfo")
	chaininfo, err := client.GetChaininfo(context.Background(), em)
	if err != nil {
		grpclog.Fatalf("%v.GetFeatures(_) = _, %v: ", client, err)
	}
	grpclog.Println(chaininfo)
}

func main() {
	flag.Parse()
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockChainClient(conn)

	printChaininfo(client, &pb.EmptyMsg{})

}
