package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type AuthnDescriptorData struct {
	Claims map[string]string `json:"claims,omitempty"`
}

type AuthnDescriptor struct {
	Type      string               `json:"type"`
	ServiceID string               `json:"service_id,omitempty"`
	Data      *AuthnDescriptorData `json:"data,omitempty"`
}

type Workload struct {
	Name             string            `json:"name"`
	Branch           string            `json:"branch"`
	Type             string            `json:"type,omitempty"`
	Owner            *Owner            `json:"owner,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors"`
	RestrictedTo     []string          `json:"restricted_to,omitempty"`
}

func (c *ClientV2) CreateWorkload(workload Workload) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Workload API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.CreateWorkloadRequest(workload)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) DeleteWorkload(workloadId string) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Workload API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.DeleteWorkloadRequest(workloadId)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) CreateWorkloadRequest(workload Workload) (*http.Request, error) {
	errors := []string{}

	err := workload.Validate()
	if err != nil {
		return nil, err
	}

	if len(workload.AuthnDescriptors) == 0 {
		errors = append(errors, "Must specify at least one authenticator in authn_descriptors")
	} else {
		for i, d := range workload.AuthnDescriptors {
			if d.Type == "" {
				errors = append(errors, fmt.Sprintf("authn_descriptors[%d] missing type", i))
			}
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}
	// Default type
	if workload.Type == "" {
		workload.Type = "other"
	}

	payload, err := json.Marshal(workload)
	if err != nil {
		return nil, err
	}

	urlPath := fmt.Sprintf("workloads/%s", c.config.Account)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
	return req, nil
}

func (c *ClientV2) DeleteWorkloadRequest(workloadID string) (*http.Request, error) {
	if workloadID == "" {
		return nil, fmt.Errorf("Must specify a Workload ID")
	}

	urlPath := fmt.Sprintf("workloads/%s/%s", c.config.Account, workloadID)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
	return req, nil
}

func (w Workload) Validate() error {
	var errs []error
	if w.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Branch"))
	}
	if w.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
