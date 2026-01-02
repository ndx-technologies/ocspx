package jws

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/crypto/ocsp"
)

var (
	ErrCertHasNoOCSP = errors.New("certificate has no OCSP")
	ErrCertUnknown   = errors.New("certificate status: unknown")
	ErrCertRevoked   = errors.New("certificate status: revoked")
)

type OCSPClientConfig struct {
	AllowNoOCSPServer bool `json:"allow_no_ocsp_server"`
	AllowUnknown      bool `json:"allow_unknown"`
}

// OCSPClient is a convenience wrapper over HTTP OCSP API.
type OCSPClient struct {
	Config OCSPClientConfig
	Client interface {
		Do(req *http.Request) (*http.Response, error)
	}
}

// VerifyCertOCSPStatus of a certificate against its issuer.
func (s OCSPClient) VerifyCertOCSPStatus(ctx context.Context, cert, issuer *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		if s.Config.AllowNoOCSPServer {
			return nil
		}
		return ErrCertHasNoOCSP
	}

	// TODO: consider other servers
	ocspURL := cert.OCSPServer[0]

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &ErrBadResponseCode{Code: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	ocspResp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return err
	}

	switch ocspResp.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return ErrCertRevoked
	case ocsp.Unknown:
		if s.Config.AllowUnknown {
			return nil
		}
		return ErrCertUnknown
	default:
		return &ErrUnexpectedOCSPStatus{Status: ocspResp.Status}
	}
}

type ErrBadResponseCode struct{ Code int }

func (e *ErrBadResponseCode) Error() string { return "bad response code: " + strconv.Itoa(e.Code) }

type ErrUnexpectedOCSPStatus struct{ Status int }

func (e *ErrUnexpectedOCSPStatus) Error() string {
	return "unexpected OCSP status: " + strconv.Itoa(e.Status)
}
