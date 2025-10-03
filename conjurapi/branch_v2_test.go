package conjurapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const testAccount = "account"
const testBranchBranch = "branch"
const testBranchName = "testBranchName"

func NewHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		if r.URL.Path == "/info" {
			response := "{\"release\":\"12.2.0\"," +
				"\"services\":{\"possum\":{\"desired\": \"i\",\"status\": \"i\",\"err\": null,\"name\": \"conjur-possum\",\"version\":\"" + MinVersion + "\",\"arch\":\"amd64\"} } }"
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(response))
			return
		}
		// authentication
		if r.URL.Path == "/authn-jwt/jwt_service/account/authenticate" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"sub":"admin","iat":"1510753259","protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`))
			return
		}

		// all requests V2 must contain V2 API HEADER
		if r.Header.Get("Accept") != v2APIHeaderBeta {
			custErr := fmt.Sprintf("Expected Accept: %s header, got: %s", v2APIHeaderBeta, r.Header.Get("Accept"))
			t.Errorf(custErr)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(custErr))
			return
		}

		body, _ := io.ReadAll(r.Body)

		// Create Branch
		customUrl := "/branches/" + testAccount
		if r.URL.Path == customUrl {
			if r.Method == http.MethodPost {
				branch := Branch{}
				err := json.Unmarshal(body, &branch)
				if err != nil {
					custErr := fmt.Sprintf("Request is not in proper json format: %s . Error: %s", body, err.Error())
					t.Errorf(custErr)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(custErr))
					return
				}
				if branch.Name != testBranchName || branch.Branch != testBranchBranch {
					custErr := fmt.Sprintf("Request is not in proper json format: %s", body)
					t.Errorf(custErr)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(custErr))
					return
				}
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"name":"testBranchName","owner":null,"branch":"branch","annotations":null}`))
				return
			}
		}
		// Read Branch
		customUrl = "/branches/" + testAccount + "/" + testBranchBranch
		if r.URL.Path == customUrl {
			if r.Method == http.MethodGet {
				response := `{"name":"` + testBranchName + `","owner": {"kind": "user","id": "user1"},"branch":"` + testBranchBranch + `","annotations": {"myannkey": "myannvalue","description": "This is my description"}}`
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				return
			}
		}
		// Read Branches
		customUrl = "/branches/" + testAccount
		if r.URL.Path == customUrl {
			if r.Method == http.MethodGet {
				response := `{"branches":[{"name":"` + testBranchName + `","owner": {"kind": "user","id": "user1"},"branch":"` + testBranchBranch + `","annotations": {"myannkey": "myannvalue","description": "This is my description"}}],"count":1}`
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				return
			}
		}
		// Update Branch
		customUrl = "/branches/" + testAccount + "/" + testBranchName
		if r.URL.Path == customUrl {
			if r.Method == http.MethodPatch {
				response := `{"branches":[{"name":"` + testBranchName + `","owner": {"kind": "user","id": "user1"},"branch":"` + testBranchBranch + `","annotations": {"myannkey": "myannvalue","description": "This is my description"}}],"count":1}`
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				return
			}
		}
		// Delete Branch
		customUrl = "/branches/" + testAccount + "/" + testBranchBranch
		if r.URL.Path == customUrl {
			if r.Method == http.MethodDelete {
				response := ``
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				return
			}
		}

		// Unknown request
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`request not recognised`))
	})
	// add more routes here
	return mux
}

func TestCreateBranchRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	branch := Branch{}
	branch.Name = testBranchName
	branch.Branch = testBranchBranch

	data, err := client.V2().CreateBranch(branch)
	if err != nil {
		t.Errorf("client.V2.CreateBranch error returned %s", err.Error())
	}
	if data == nil {
		t.Errorf("client.V2.CreateBranch data returned nil")
	}
}

func TestReadBranchRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	data, err := client.V2().ReadBranch(testBranchBranch)
	if err != nil {
		t.Errorf("client.V2.CreateBranch error returned %s", err.Error())
	}
	if data == nil {
		t.Errorf("client.V2.CreateBranch data returned nil")
	}
}

func TestReadBranchesRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	data, err := client.V2().ReadBranches(nil)
	if err != nil {
		t.Errorf("client.V2.CreateBranch error returned %s", err.Error())
	}
	if data.Count == 0 {
		t.Errorf("client.V2.CreateBranch, branches response is empty")
	}
}

func TestUpdateBranchRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	owner := &Owner{
		Kind: "user",
		Id:   "user1",
	}
	annotations := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	data, err := client.V2().UpdateBranch(Branch{
		Name:        testBranchName,
		Owner:       owner,
		Annotations: annotations,
	})
	if err != nil {
		t.Errorf("client.V2.UpdateBranch error returned %s", err.Error())
	}
	if data == nil {
		t.Errorf("client.V2.UpdateBranch data returned nil")
	}
}

func TestDeleteBranchRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	data, err := client.V2().DeleteBranch(testBranchBranch)
	if err != nil {
		t.Errorf("client.V2.CreateBranch error returned %s", err.Error())
	}
	if data == nil {
		t.Errorf("client.V2.CreateBranch data returned nil")
	}
}

func GetConfigForTest(url string) Config {
	config := Config{}
	config.ApplianceURL = url
	config.Account = testAccount
	config.AuthnType = "jwt"
	config.ServiceID = "jwt_service"
	config.JWTContent = "{\"protected\":\"true\",\"payload\":\"true\",\"signature\":\"yes\"}"
	return config
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

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeaderBeta {
		t.Errorf("Error Header %s not found", v2APIHeaderBeta)
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

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeaderBeta {
		t.Errorf("Error Header %s not found", v2APIHeaderBeta)
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

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeaderBeta {
		t.Errorf("Error Header %s not found", v2APIHeaderBeta)
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
	branchName := testBranchName

	_, err = client.V2().UpdateBranchRequest("", nil, nil)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	owner := &Owner{
		Kind: "user",
		Id:   "user1",
	}
	annotations := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	request, err := client.V2().UpdateBranchRequest(branchName, owner, annotations)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeaderBeta {
		t.Errorf("Error Header %s not found", v2APIHeaderBeta)
		return
	}

	reqUrl := "localhost/branches/" + account + "/" + branchName
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

	client.config.Account = testAccount

	request, err := client.V2().DeleteBranchRequest(ident)
	if err != nil {
		t.Errorf("Error Test failed %s", err.Error())
		return
	}

	if request.Header.Get(v2APIOutgoingHeaderID) != v2APIHeaderBeta {
		t.Errorf("Error Header %s not found", v2APIHeaderBeta)
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
