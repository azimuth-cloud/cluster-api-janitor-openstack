package openstack

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func loadCACert(cfg *tls.Config, cacert string) error {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(cacert)) {
		return fmt.Errorf("failed to append CA certificate")
	}
	cfg.RootCAs = pool
	return nil
}
