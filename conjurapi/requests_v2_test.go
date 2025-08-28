package conjurapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func newTestClient(serverURL string) Client {
	return Client{
		config: Config{
			ApplianceURL: serverURL,
			Account:      "myTestAccount",
		},
	}
}

func TestClientV2_CreateBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	branch := Branch{}

	_, err = client.V2().CreateBranchRequest(branch)
	if err == nil {
		return
	}
	if !strings.Contains(fmt.Sprint(err), "Branch attribute Branch") {
		t.Errorf("Error string do not contain information about missing Branch")
		return
	}

	if !strings.Contains(fmt.Sprint(err), "Branch attribute Name") {
		t.Errorf("Error string do not contain information about missing Name")
		return
	}

	branch.Name = "Name"
	branch.Branch = "Branch"

	request, err := client.V2().CreateBranchRequest(branch)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeader {
		t.Errorf("Error Header %s not found", v2APIHeader)
		return
	}

	request, err = client.V2().CreateBranchRequest(branch)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.URL.Path != "localhost/branches/account" {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, "localhost/branches/account")
		return
	}

	if request.Method != http.MethodPost {
		t.Errorf("Error wrong http method used")
		return
	}
}

func TestClientV2_ReadBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	ident := "super/hiper/test/id"
	account := "account"

	_, err = client.V2().ReadBranchRequest(ident)
	if err == nil {
		return
	}
	if !strings.Contains(fmt.Sprint(err), "Account") {
		t.Errorf("Error string do not contain information about missing Account")
		return
	}

	if !strings.Contains(fmt.Sprint(err), "identifier") {
		t.Errorf("Error string do not contain information about missing identifier")
		return
	}

	request, err := client.V2().ReadBranchRequest(ident)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeader {
		t.Errorf("Error Header %s not found", v2APIHeader)
		return
	}

	request, err = client.V2().ReadBranchRequest(ident)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl := "localhost/branches/" + account
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	if request.Method != http.MethodGet {
		t.Errorf("Error wrong http method used")
		return
	}
}

func TestClientV2_ReadBranchesRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	client.config.Account = ""
	_, err = client.V2().ReadBranchesRequest(nil)
	if err == nil {
		return
	}
	if !strings.Contains(fmt.Sprint(err), "Account") {
		t.Errorf("Error string do not contain information about missing Account")
		return
	}

	client.config.Account = testAccount
	request, err := client.V2().ReadBranchesRequest(nil)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeader {
		t.Errorf("Error Header %s not found", v2APIHeader)
		return
	}

	request, err = client.V2().ReadBranchesRequest(nil)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl := "localhost/branches/" + client.config.Account
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	filter := BranchFilter{Offset: 10}

	request, err = client.V2().ReadBranchesRequest(&filter)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl = "localhost/branches/" + client.config.Account
	reqQuery := "offset=" + strconv.Itoa(filter.Offset)
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	if request.URL.RawQuery != reqQuery {
		t.Errorf("Error Query is not proper: %s, should be: %s", request.URL.RawQuery, reqQuery)
		return
	}

	filter.Offset = 10
	filter.Limit = 10
	request, err = client.V2().ReadBranchesRequest(&filter)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl = "localhost/branches/" + client.config.Account
	reqQuery = "offset=" + strconv.Itoa(filter.Offset) + "&limit=" + strconv.Itoa(filter.Limit)
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	if request.URL.RawQuery != reqQuery {
		t.Errorf("Error Query is not proper: %s, should be: %s", request.URL.RawQuery, reqQuery)
		return
	}

	if request.Method != http.MethodGet {
		t.Errorf("Error wrong http method used")
		return
	}
}

func TestClientV2_UpdateBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	account := "account"
	ident := "super/hiper/test/id"
	branch := Branch{}

	_, err = client.V2().UpdateBranchRequest(branch)
	if err == nil {
		return
	}
	if !strings.Contains(fmt.Sprint(err), "Branch attribute Branch") {
		t.Errorf("Error string do not contain information about missing Branch.Branch")
		return
	}

	if !strings.Contains(fmt.Sprint(err), "Branch attribute Name") {
		t.Errorf("Error string do not contain information about missing Branch.Name")
		return
	}

	branch.Branch = ident
	branch.Name = testBranchName

	request, err := client.V2().UpdateBranchRequest(branch)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeader {
		t.Errorf("Error Header %s not found", v2APIHeader)
		return
	}

	request, err = client.V2().UpdateBranchRequest(branch)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl := "localhost/branches/" + account + "/" + ident
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	if request.Method != http.MethodPatch {
		t.Errorf("Error wrong http method used")
		return
	}
}

func TestClientV2_DeleteBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	client.config.Account = ""

	ident := "super/hiper/test/id"

	_, err = client.V2().DeleteBranchRequest("")
	if err == nil {
		return
	}
	if !strings.Contains(fmt.Sprint(err), "Account") {
		t.Errorf("Error string do not contain information about missing Account")
		return
	}

	client.config.Account = testAccount

	request, err := client.V2().DeleteBranchRequest(ident)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeader {
		t.Errorf("Error Header %s not found", v2APIHeader)
		return
	}

	request, err = client.V2().DeleteBranchRequest(ident)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	reqUrl := "localhost/branches/" + testAccount + "/" + ident
	if request.URL.Path != reqUrl {
		t.Errorf("Error Url is not proper: %s, should be: %s", request.URL.Path, reqUrl)
		return
	}

	if request.Method != http.MethodDelete {
		t.Errorf("Error wrong http method used")
		return
	}
}

func validWorkload() Workload {
	return Workload{
		Name:   "testWorkload",
		Branch: "data",
		AuthnDescriptors: []AuthnDescriptor{
			{Type: "authn-jwt", ServiceID: "jwt_service"},
		},
	}
}

func TestCreateWorkloadRequest_MinimalSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Error wrong http method used")
		}
		if r.URL.Path != "/workloads/myTestAccount" {
			t.Errorf("Error Url is not proper: %s, should be: %s", r.URL.Path, "localhost/workloads/myTestAccount")
		}
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "testWorkload" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Branch != "data" {
			t.Errorf("Unexpected branch: %s", workload.Branch)
		}
		if workload.Type != "other" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		if len(workload.AuthnDescriptors) != 1 || workload.AuthnDescriptors[0].Type != "authn-jwt" || workload.AuthnDescriptors[0].ServiceID != "jwt_service" {
			t.Errorf("Unexpected authn_descriptors: %+v", workload.AuthnDescriptors)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)

	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_JenkinsJWTWithAnnotationsSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "jenkins-ci-workload" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Type != "Jenkins" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		if workload.Owner == nil || workload.Owner.Kind != "user" || workload.Owner.Id != "e2e_test@cyberark.com" {
			t.Errorf("Unexpected owner: %+v", workload.Owner)
		}
		expectedAnn := map[string]string{"my_devops_team": "CI_CD"}
		if !reflect.DeepEqual(workload.Annotations, expectedAnn) {
			t.Errorf("Unexpected annotations. got=%s want=%s", workload.Annotations, expectedAnn)
		}
		if len(workload.AuthnDescriptors) != 1 {
			t.Errorf("Expected 1 authn descriptor, got %d", len(workload.AuthnDescriptors))
		}
		ad := workload.AuthnDescriptors[0]
		if ad.Type != "authn-jwt" || ad.ServiceID != "jwt_service" {
			t.Errorf("Unexpected authn descriptor: %+v", ad)
		}
		if ad.Data == nil || ad.Data.Claims["jenkins_task_noun"] != "Build" ||
			ad.Data.Claims["jenkins_pronoun"] != "CC" ||
			ad.Data.Claims["jenkins_parent_full_name"] != "/main" {
			t.Errorf("Unexpected claims: %+v", ad.Data)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workloadData := Workload{
		Name:   "jenkins-ci-workload",
		Branch: "data",
		Type:   "Jenkins",
		Owner: &Owner{
			Kind: "user",
			Id:   "e2e_test@cyberark.com",
		},
		Annotations: map[string]string{
			"my_devops_team": "CI_CD",
		},
		AuthnDescriptors: []AuthnDescriptor{
			{
				Type:      "authn-jwt",
				ServiceID: "jwt_service",
				Data: &AuthnDescriptorData{
					Claims: map[string]string{
						"jenkins_task_noun":        "Build",
						"jenkins_pronoun":          "CC",
						"jenkins_parent_full_name": "/main",
					},
				},
			},
		},
	}

	req, err := c.V2().CreateWorkloadRequest(workloadData)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_ApiKeyRestrictedIPsSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "api-key-client" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Branch != "data/us-east1/test" {
			t.Errorf("Unexpected branch: %s", workload.Branch)
		}
		if len(workload.RestrictedTo) != 2 || workload.RestrictedTo[0] != "1.2.4.5" || workload.RestrictedTo[1] != "10.20.30.10" {
			t.Errorf("Unexpected restricted_to: %s", workload.RestrictedTo)
		}
		if len(workload.AuthnDescriptors) != 1 || workload.AuthnDescriptors[0].Type != "authn_api_key" {
			t.Errorf("Unexpected authn_descriptors: %+v", workload.AuthnDescriptors)
		}
		if workload.Owner == nil || workload.Owner.Id != "e2e_test@cyberark.com" {
			t.Errorf("Unexpected owner: %+v", workload.Owner)
		}
		if workload.Type != "other" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workloadData := Workload{
		Name:   "api-key-client",
		Branch: "data/us-east1/test",
		Owner: &Owner{
			Kind: "user",
			Id:   "e2e_test@cyberark.com",
		},
		RestrictedTo: []string{"1.2.4.5", "10.20.30.10"},
		AuthnDescriptors: []AuthnDescriptor{
			{Type: "authn_api_key"},
		},
	}

	req, err := c.V2().CreateWorkloadRequest(workloadData)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_MissingNameValidationError422(t *testing.T) {
	c := newTestClient("http://conjur.test")

	workload := validWorkload()
	workload.Name = ""

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err == nil {
		t.Errorf("Expected error for missing name, got nil (request=%v)", req)
	}
	if !strings.Contains(err.Error(), "Workload Name") {
		t.Errorf("Expected error to mention Workload Name, got %s", err)
	}
}

func TestCreateWorkloadRequest_DuplicateWorkload409(t *testing.T) {
	created := map[string]bool{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		if created[workload.Name] {
			w.WriteHeader(http.StatusConflict)
			return
		}
		created[workload.Name] = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workload := validWorkload()

	// First create (201)
	req1, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp1.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp1.StatusCode)
	}

	// Second create (409)
	req2, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("Expected 409, got %d", resp2.StatusCode)
	}
}

func TestCreateWorkloadRequest_MalformedIPs422(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		for _, ip := range workload.RestrictedTo {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)

	workload := validWorkload()
	workload.RestrictedTo = []string{"1.2.3.999", "10.0.0.1"}

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_MissingContentType400(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != v2APIHeader {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		t.Errorf("Expected no Content-Type header set by builder, found %s", ct)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing Content-Type, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_Unauthorized401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_Forbidden403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		if workload.Branch == "forbidden/branch" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workload := validWorkload()
	workload.Branch = "forbidden/branch"

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

func TestDeleteWorkloadRequest_MissingIDError(t *testing.T) {
	c := newTestClient("http://conjur.test")
	_, err := c.V2().DeleteWorkloadRequest("")
	if err == nil || !strings.Contains(err.Error(), "Workload ID") {
		t.Errorf("Expected error about Workload ID, got %s", err)
	}
}

func TestDeleteWorkloadRequest_Unauthorized401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().DeleteWorkloadRequest("testWorkload")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

func TestDeleteWorkloadRequest_Forbidden403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "protected") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().DeleteWorkloadRequest("protectedWorkload")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}
