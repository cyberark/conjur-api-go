package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
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

	issueJSON, err := json.Marshal(issue)

	path := fmt.Sprintf("issuers/%s/issue", issuerName)
	//path := "issue"

	c.issuersURL(c.config.Account)
	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodPost,
		branchURL,
		bytes.NewBuffer(issueJSON),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	request.Header.Add("Content-Type", "application/json")

	return request, nil
}

func (c *ClientV2) CertificateIssue(issuerName string, issue Issue) (*CertificateResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Issue API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.CertificateIssueRequest(issuerName, issue)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	issueResp := CertificateResponse{}
	err = json.Unmarshal(bodyData, &issueResp)
	if err != nil {
		return nil, err
	}

	return &issueResp, nil
}

func (c *ClientV2) CertificateSignRequest(issuerName string, sign Sign) (*http.Request, error) {
	err := sign.Validate()
	if err != nil {
		return nil, err
	}

	signJSON, err := json.Marshal(sign)

	path := fmt.Sprintf("issuers/%s/sign", issuerName)

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodPost,
		branchURL,
		bytes.NewBuffer(signJSON),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	request.Header.Add("Content-Type", "application/json")

	return request, nil
}

func (c *ClientV2) CertificateSign(issuerName string, sign Sign) (*CertificateResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Issue API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.CertificateSignRequest(issuerName, sign)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	issueResp := CertificateResponse{}
	err = json.Unmarshal(bodyData, &issueResp)
	if err != nil {
		return nil, err
	}

	return &issueResp, nil
}
