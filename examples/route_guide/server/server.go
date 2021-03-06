/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a simple gRPC server that demonstrates how to use gRPC-Go libraries
// to perform unary, client streaming, server streaming and full duplex RPCs.
//
// It implements the route guide service whose definition can be found in routeguide/route_guide.proto.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"

	"github.com/golang/protobuf/proto"

	pb "github.com/zhangyongjiang/grpc-go/examples/route_guide/routeguide"
	"github.com/zhangyongjiang/grpc-go/examples/route_guide/utils"
	"crypto/x509"
	ctls "crypto/tls"
	"crypto/rsa"
	"reflect"
	"encoding/pem"
)

var (
	tls        = flag.Bool("tls", true, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "testdata/server1.pem", "The TLS cert file")
	keyFile    = flag.String("key_file", "testdata/server1.key", "The TLS key file")
	jsonDBFile = flag.String("json_db_file", "testdata/route_guide_db.json", "A json file containing a list of features")
	port       = flag.Int("port", 9090, "The server port")
	chainFile  = flag.String("chain_info_file", "testdata/chaininfo.json", "A json file containing bc info")
)

type routeGuideServer struct {
	savedFeatures []*pb.Feature
	routeNotes    map[string][]*pb.RouteNote
	savedChaininfo *pb.Chaininfo
}

// GetFeature returns the feature at the given point.
func (s *routeGuideServer) GetFeature(ctx context.Context, point *pb.Point) (*pb.Feature, error) {
	for _, feature := range s.savedFeatures {
		if proto.Equal(feature.Location, point) {
			return feature, nil
		}
	}
	// No feature was found, return an unnamed feature
	return &pb.Feature{Location: point}, nil
}

// GetChaininfo returns the chaininfo.
func (s *routeGuideServer) GetChaininfo(ctx context.Context, em *pb.EmptyMsg) (*pb.Chaininfo, error) {
	peer, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
		fmt.Println(tlsInfo)

		v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
		fmt.Println(v)
		fmt.Printf("%v - %v\n", peer.Addr.String(), v)

		//v := tlsInfo.State.VerifiedChains
		//fmt.Println(v)


		for _, v := range tlsInfo.State.PeerCertificates {
			fmt.Println("Client public key is:")
			fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
			fmt.Println(v.EmailAddresses)
		}
	}

	s.savedChaininfo.Signature = ""
	var err error
	s.savedChaininfo.Signature, err = utils.SignMessage(s.savedChaininfo, srvSecret)
	if err != nil {
		fmt.Println("server side sig error ")
		fmt.Println(err)
	} else {
		fmt.Println("server side sig : " + s.savedChaininfo.Signature)
	}

	return s.savedChaininfo, nil
}

// ListFeatures lists all features contained within the given bounding Rectangle.
func (s *routeGuideServer) ListFeatures(rect *pb.Rectangle, stream pb.RouteGuide_ListFeaturesServer) error {
	for _, feature := range s.savedFeatures {
		if inRange(feature.Location, rect) {
			if err := stream.Send(feature); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecordRoute records a route composited of a sequence of points.
//
// It gets a stream of points, and responds with statistics about the "trip":
// number of points,  number of known features visited, total distance traveled, and
// total time spent.
func (s *routeGuideServer) RecordRoute(stream pb.RouteGuide_RecordRouteServer) error {
	var pointCount, featureCount, distance int32
	var lastPoint *pb.Point
	startTime := time.Now()
	for {
		point, err := stream.Recv()
		if err == io.EOF {
			endTime := time.Now()
			return stream.SendAndClose(&pb.RouteSummary{
				PointCount:   pointCount,
				FeatureCount: featureCount,
				Distance:     distance,
				ElapsedTime:  int32(endTime.Sub(startTime).Seconds()),
			})
		}
		if err != nil {
			return err
		}
		pointCount++
		for _, feature := range s.savedFeatures {
			if proto.Equal(feature.Location, point) {
				featureCount++
			}
		}
		if lastPoint != nil {
			distance += calcDistance(lastPoint, point)
		}
		lastPoint = point
	}
}

// RouteChat receives a stream of message/location pairs, and responds with a stream of all
// previous messages at each of those locations.
func (s *routeGuideServer) RouteChat(stream pb.RouteGuide_RouteChatServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		key := serialize(in.Location)
		if _, present := s.routeNotes[key]; !present {
			s.routeNotes[key] = []*pb.RouteNote{in}
		} else {
			s.routeNotes[key] = append(s.routeNotes[key], in)
		}
		for _, note := range s.routeNotes[key] {
			if err := stream.Send(note); err != nil {
				return err
			}
		}
	}
}

// loadFeatures loads features from a JSON file.
func (s *routeGuideServer) loadFeatures(filePath string) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		grpclog.Fatalf("Failed to load default features: %v", err)
	}
	if err := json.Unmarshal(file, &s.savedFeatures); err != nil {
		grpclog.Fatalf("Failed to load default features: %v", err)
	}
}

// loadChaininfo loads chain from a JSON file.
func (s *routeGuideServer) loadChaininfo(filePath string) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		grpclog.Fatalf("Failed to load default chaininfo: %v", err)
	}
	if err := json.Unmarshal(file, &s.savedChaininfo); err != nil {
		grpclog.Fatalf("Failed to load default chaininfo: %v", err)
	}
}

func toRadians(num float64) float64 {
	return num * math.Pi / float64(180)
}

// calcDistance calculates the distance between two points using the "haversine" formula.
// This code was taken from http://www.movable-type.co.uk/scripts/latlong.html.
func calcDistance(p1 *pb.Point, p2 *pb.Point) int32 {
	const CordFactor float64 = 1e7
	const R float64 = float64(6371000) // metres
	lat1 := float64(p1.Latitude) / CordFactor
	lat2 := float64(p2.Latitude) / CordFactor
	lng1 := float64(p1.Longitude) / CordFactor
	lng2 := float64(p2.Longitude) / CordFactor
	φ1 := toRadians(lat1)
	φ2 := toRadians(lat2)
	Δφ := toRadians(lat2 - lat1)
	Δλ := toRadians(lng2 - lng1)

	a := math.Sin(Δφ/2)*math.Sin(Δφ/2) +
		math.Cos(φ1)*math.Cos(φ2)*
			math.Sin(Δλ/2)*math.Sin(Δλ/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	distance := R * c
	return int32(distance)
}

func inRange(point *pb.Point, rect *pb.Rectangle) bool {
	left := math.Min(float64(rect.Lo.Longitude), float64(rect.Hi.Longitude))
	right := math.Max(float64(rect.Lo.Longitude), float64(rect.Hi.Longitude))
	top := math.Max(float64(rect.Lo.Latitude), float64(rect.Hi.Latitude))
	bottom := math.Min(float64(rect.Lo.Latitude), float64(rect.Hi.Latitude))

	if float64(point.Longitude) >= left &&
		float64(point.Longitude) <= right &&
		float64(point.Latitude) >= bottom &&
		float64(point.Latitude) <= top {
		return true
	}
	return false
}

func serialize(point *pb.Point) string {
	return fmt.Sprintf("%d %d", point.Latitude, point.Longitude)
}

func newServer() *routeGuideServer {
	s := new(routeGuideServer)
	s.loadFeatures(*jsonDBFile)
	s.loadChaininfo(*chainFile)
	s.routeNotes = make(map[string][]*pb.RouteNote)
	return s
}

var srvSecret *rsa.PrivateKey
func main() {
	fmt.Println("hi")
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		ta := credentials.NewTLS(getTlsConfig())
		opts = []grpc.ServerOption{grpc.Creds(ta)}
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterRouteGuideServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}

func getTlsConfig1() *ctls.Config {
	certs := utils.Certs{}
	certs.Init()

	_, rootCertPEM, _ := certs.GetServerCertificate()
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certs.ServerPrivateKey),
	})
	rootTLSCert, _ := ctls.X509KeyPair(rootCertPEM, rootKeyPEM)

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCertPEM)

	return &ctls.Config{
		Certificates: []ctls.Certificate{rootTLSCert},
		ClientCAs:    certPool,
		ClientAuth:   ctls.RequireAndVerifyClientCert,
	}
}

func getTlsConfig() *ctls.Config {
	certificate, _ := ctls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
	srvSecret = reflect.ValueOf(certificate.PrivateKey).Interface().(*rsa.PrivateKey)

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		fmt.Printf("could not read ca certificate: %s", err)
		return nil
	}
	// Append the certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		fmt.Printf("failed to append ca certs")
		return nil
	}
	return &ctls.Config{
		Certificates: []ctls.Certificate{certificate},
		ClientCAs:    certPool,
		ClientAuth:   ctls.RequireAndVerifyClientCert,
	}
}
