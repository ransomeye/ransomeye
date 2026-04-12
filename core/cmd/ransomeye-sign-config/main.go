// ransomeye-sign-config signs configs/common.yaml (or a copy) with the Mishka intermediate
// PKCS#8 private key so core can load it with LoadVerifiedCommonConfig in production.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"ransomeye/core/internal/config"
)

func main() {
	configPath := flag.String("config", "", "path to common.yaml")
	keyPath := flag.String("key", "", "path to PKCS#8 PEM private key (RSA or Ed25519)")
	outPath := flag.String("out", "", "output path (default: overwrite -config)")
	verifyCert := flag.String("verify-cert", "", "optional PEM CA/intermediate cert to verify signature after signing")
	flag.Parse()
	if *configPath == "" || *keyPath == "" {
		log.Fatal("usage: ransomeye-sign-config -config common.yaml -key intermediate_ca.key [-out signed.yaml] [-verify-cert intermediate_ca.crt]")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config.CommonConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := config.ParsePKCS8PrivateKeyAny(keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err = config.SignCommonConfig(cfg, priv)
	if err != nil {
		log.Fatal(err)
	}
	if *verifyCert != "" {
		cert, err := loadFirstCert(*verifyCert)
		if err != nil {
			log.Fatal(err)
		}
		if err := config.VerifyCommonConfig(cfg, cert); err != nil {
			log.Fatalf("post-sign verify: %v", err)
		}
	}
	out := *outPath
	if out == "" {
		out = *configPath
	}
	outBytes, err := yaml.Marshal(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(out, outBytes, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", out)
}

func loadFirstCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no PEM certificate in %s", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
}
