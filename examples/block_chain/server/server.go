package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/grpclog"

	pb "google.golang.org/grpc/examples/block_chain/blockchain"
)

var (
	port       = flag.Int("port", 9090, "The server port")
	chainFile  = flag.String("chain_info_file", "testdata/chaininfo.json", "A json file containing bc info")
)

type blockChainServer struct {
	savedChaininfo *pb.Chaininfo
}

// GetChaininfo returns the chaininfo.
func (s *blockChainServer) GetChaininfo(ctx context.Context, em *pb.EmptyMsg) (*pb.Chaininfo, error) {
	return s.savedChaininfo, nil
}

// loadChaininfo loads chain from a JSON file.
func (s *blockChainServer) loadChaininfo(filePath string) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		grpclog.Fatalf("Failed to load default chaininfo: %v", err)
	}
	if err := json.Unmarshal(file, &s.savedChaininfo); err != nil {
		grpclog.Fatalf("Failed to load default chaininfo: %v", err)
	}
}

func newServer() *blockChainServer {
	s := new(blockChainServer)
	s.loadChaininfo(*chainFile)
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterBlockChainServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
