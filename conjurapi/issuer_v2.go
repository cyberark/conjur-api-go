package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
)

type IssuerSubject struct {
	CommonName   string   `json:"common_name"`
	Organization string   `json:"organization,omitempty"`
	OrgUnits     []string `json:"org_units,omitempty"`
	Locality     string   `json:"locality,omitempty"`
	State        string   `json:"state,omitempty"`
	Country      string   `json:"country,omitempty"`
}

func (s IssuerSubject) Validate() error {
	var errs []error
	if s.CommonName == "" {
		errs = append(errs, fmt.Errorf("Missing required Subject attribute CommonName"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type AltNames struct {
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EMailAddresses []string `json:"email_addresses,omitempty"`
	Uris           []string `json:"uris,omitempty"`
}

type Issue struct {
	Subject       IssuerSubject `json:"subject"`
	KeyType       string        `json:"key_type,omitempty"`
	AltNames      AltNames      `json:"alt_names,omitempty"`
	TTL           string        `json:"ttl,omitempty"`
	Zone          string        `json:"zone,omitempty"`
	IgnoreStorage bool          `json:"ignore_storage,omitempty"`
}

func (i Issue) Validate() error {
	return i.Subject.Validate()
}

type CertificateResponse struct {
	Certificate string   `json:"certificate,omitempty"`
	Chain       []string `json:"chain,omitempty"`
	PrivateKey  string   `json:"private_key,omitempty"`
}

type Sign struct {
	Csr  string `json:"csr"`
	Zone string `json:"zone,omitempty"`
	TTL  string `json:"ttl,omitempty"`
}

func (s Sign) Validate() error {
	var errs []error
	if s.Csr == "" {
		errs = append(errs, fmt.Errorf("Missing required Sign attribute csr"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *ClientV2) CertificateIssueRequest(issuerName string, issue Issue) (*http.Request, error) {
	err := issue.Validate()
	if err != nil {
		return nil, err
	}

	err = issue.Subject.Validate()
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("issuers/%s/issue", issuerName)

	c.issuersURL(c.config.Account)
	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	return newV2JSONRequest(http.MethodPost, branchURL, issue, v2APIHeaderBeta)
}

func (c *ClientV2) CertificateIssue(issuerName string, issue Issue) (*CertificateResponse, error) {
	req, err := c.CertificateIssueRequest(issuerName, issue)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[CertificateResponse](c, req)
}

func (c *ClientV2) CertificateSignRequest(issuerName string, sign Sign) (*http.Request, error) {
	err := sign.Validate()
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("issuers/%s/sign", issuerName)

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	return newV2JSONRequest(http.MethodPost, branchURL, sign, v2APIHeaderBeta)
}

func (c *ClientV2) CertificateSign(issuerName string, sign Sign) (*CertificateResponse, error) {
	req, err := c.CertificateSignRequest(issuerName, sign)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[CertificateResponse](c, req)
}
