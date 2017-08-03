package utils


import (
	"encoding/base64"
	"crypto/sha256"
	"github.com/golang/protobuf/proto"
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"
	"crypto/x509"
	"crypto/tls"
	"math/big"
	"crypto/x509/pkix"
	"time"
	"log"
	"os"
	"encoding/pem"
	"fmt"
	"errors"
	"net"
)

type Certs struct {
	CA               *x509.Certificate
	CAPrivateKey     *rsa.PrivateKey
	ServerPrivateKey *rsa.PrivateKey
	ClientPrivateKey *rsa.PrivateKey
}

func (certs *Certs)Init()  {
	certs.CA = CreateCertificateAuthority()
	certs.CAPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	certs.ServerPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	certs.ClientPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (certs *Certs)GetServerCertificate() (cert *x509.Certificate, certPEM []byte, err error) {
	return CreateCert(certs.CA, certs.CA, certs.ServerPrivateKey.PublicKey, certs.ServerPrivateKey)
}

func (certs *Certs)GetClientCertificate() (cert *x509.Certificate, certPEM []byte, err error) {
	return CreateCert(certs.CA, certs.CA, certs.ClientPrivateKey.PublicKey, certs.ClientPrivateKey)
}

func (certs *Certs) WriteServerPublicKeyFile(filename string)  {
	pub := &certs.ServerPrivateKey.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, certs.CA, certs.CA, pub, certs.ServerPrivateKey)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}
	certOut, err := os.Create(filename)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	certOut.Close()
}

func (certs *Certs) WriteServerPrivateKeyFile(filename string)  {
	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certs.ServerPrivateKey)})
	keyOut.Close()
}

func (certs *Certs) WriteClientPublicKeyFile(filename string)  {
	pub := &certs.ClientPrivateKey.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, certs.CA, certs.CA, pub, certs.ClientPrivateKey)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}
	certOut, err := os.Create(filename)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	certOut.Close()
}

func (certs *Certs) WriteClientPrivateKeyFile(filename string)  {
	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certs.ClientPrivateKey)})
	keyOut.Close()
}

func CreateCertificateAuthority() *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	return  ca
}


func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Yhat, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func CreateKeyPair() {
	// generate a new key-pair
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	rootCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	// describe what the certificate will be used for
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
}