package conjurapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			t.Errorf("Expected Accept: %s header, got: %s", v2APIHeaderBeta, r.Header.Get("Accept"))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("invalid Accept header"))
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
					t.Errorf("Request is not in proper json format: %s . Error: %s", body, err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("invalid request body"))
					return
				}
				if branch.Name != testBranchName || branch.Branch != testBranchBranch {
					t.Errorf("Request is not in proper json format: %s", body)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("invalid branch payload"))
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
		// Update Branch: PATCH on the full identifier returns the branch; only annotations are allowed.
		customUrl = "/branches/" + testAccount + "/" + testBranchBranch + "/" + testBranchName
		if r.URL.Path == customUrl {
			if r.Method == http.MethodPatch {
				var patch map[string]interface{}
				_ = json.Unmarshal(body, &patch)
				for k := range patch {
					if k != "annotations" {
						t.Errorf("UpdateBranch sent unpermitted field %q (service would 422)", k)
						w.WriteHeader(http.StatusUnprocessableEntity)
						w.Write([]byte(`{"error":{"code":"unprocessable_entity","message":"Unexpected parameters: ` + k + `"}}`))
						return
					}
				}
				response := `{"name":"` + testBranchName + `","branch":"` + testBranchBranch + `","annotations": {"myannkey": "myannvalue"},"created_at":"2026-01-02T03:04:05Z"}`
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				return
			}
		}
		// Delete Branch: 204 No Content.
		customUrl = "/branches/" + testAccount + "/" + testBranchBranch
		if r.URL.Path == customUrl {
			if r.Method == http.MethodDelete {
				w.Header().Add(v2APIIncomingHeaderID, v2APIHeaderBeta)
				w.WriteHeader(http.StatusNoContent)
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

	annotations := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	// With a parent Branch set, UpdateBranch must PATCH the full identifier.
	data, err := client.V2().UpdateBranch(Branch{
		Name:        testBranchName,
		Branch:      testBranchBranch,
		Annotations: annotations,
	})
	if err != nil {
		t.Errorf("client.V2.UpdateBranch error returned %s", err.Error())
	}
	if data == nil {
		t.Fatalf("client.V2.UpdateBranch data returned nil")
	}
	assert.Equal(t, testBranchName, data.Name)
	assert.Equal(t, testBranchBranch, data.Branch)
	assert.Equal(t, map[string]string{"myannkey": "myannvalue"}, data.Annotations)
	assert.Equal(t, "2026-01-02T03:04:05Z", data.CreatedAt)
}

func TestDeleteBranchRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(NewHandler(t))
	defer server.Close()

	config := GetConfigForTest(server.URL)
	client, err := NewClientFromJwt(config)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	err = client.V2().DeleteBranch(testBranchBranch)
	if err != nil {
		t.Errorf("client.V2.DeleteBranch error returned %s", err.Error())
	}
}

func GetConfigForTest(url string) Config {
	config := Config{}
	config.ApplianceURL = url
	config.Account = testAccount
	config.AuthnType = "jwt"
	config.ServiceID = "jwt_service"
	config.JWTContent = "{\"protected\":\"true\",\"payload\":\"true\",\"signature\":\"yes\"}"
	config.CredentialStorage = CredentialStorageNone // keep test tokens out of ~/.netrc and the keychain
	return config
}

func TestClientV2_CreateBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	branch := Branch{}

	_, err = client.V2().CreateBranchRequest(branch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Branch attribute Branch")
	assert.Contains(t, err.Error(), "Branch attribute Name")

	branch.Name = "Name"
	branch.Branch = "Branch"

	req, err := client.V2().CreateBranchRequest(branch)
	assert.NoError(t, err)
	assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "localhost/branches/account", req.URL.Path)
	assert.Equal(t, http.MethodPost, req.Method)
	body, _ := io.ReadAll(req.Body)
	assert.NotContains(t, string(body), "owner")

	branch.Owner = &Owner{Kind: "user", Id: "user1"}
	req, err = client.V2().CreateBranchRequest(branch)
	assert.NoError(t, err)
	body, _ = io.ReadAll(req.Body)
	assert.Contains(t, string(body), `"owner":{"kind":"user","id":"user1"}`)
}

func TestClientV2_ReadBranchRequest(t *testing.T) {
	client, err := NewClientFromJwt(GetConfigForTest("localhost"))
	require.NoError(t, err)
	ident := "super/hiper/test/id"

	_, err = client.V2().ReadBranchRequest("")
	assert.ErrorContains(t, err, "identifier")

	request, err := client.V2().ReadBranchRequest(ident)
	require.NoError(t, err)
	assert.Equal(t, v2APIHeaderBeta, request.Header.Get(v2APIOutgoingHeaderID))
	assert.Equal(t, "localhost/branches/"+testAccount+"/"+ident, request.URL.Path)
	assert.Equal(t, http.MethodGet, request.Method)

	// Secrets Manager SaaS leaves the account out of the path.
	client.config.Environment = EnvironmentSaaS
	request, err = client.V2().ReadBranchRequest(ident)
	require.NoError(t, err)
	assert.Equal(t, "localhost/branches/"+ident, request.URL.Path)
}

func TestClientV2_ReadBranchesRequest(t *testing.T) {
	client, err := NewClientFromJwt(GetConfigForTest("localhost"))
	require.NoError(t, err)

	request, err := client.V2().ReadBranchesRequest(nil)
	require.NoError(t, err)
	assert.Equal(t, v2APIHeaderBeta, request.Header.Get(v2APIOutgoingHeaderID))
	assert.Equal(t, "localhost/branches/"+testAccount, request.URL.Path)
	assert.Empty(t, request.URL.RawQuery)
	assert.Equal(t, http.MethodGet, request.Method)

	// Zero values are left out, so the server's defaults apply.
	request, err = client.V2().ReadBranchesRequest(&BranchFilter{})
	require.NoError(t, err)
	assert.Empty(t, request.URL.RawQuery)

	request, err = client.V2().ReadBranchesRequest(&BranchFilter{Limit: 10, Offset: 20})
	require.NoError(t, err)
	assert.Equal(t, "limit=10&offset=20", request.URL.RawQuery)

	// Secrets Manager SaaS leaves the account out of the path.
	client.config.Environment = EnvironmentSaaS
	request, err = client.V2().ReadBranchesRequest(nil)
	require.NoError(t, err)
	assert.Equal(t, "localhost/branches", request.URL.Path)
}

func TestClientV2_UpdateBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	account := "account"
	branchName := testBranchName

	_, err = client.V2().UpdateBranchRequest("", nil, nil)
	assert.ErrorContains(t, err, "identifier")

	annotations := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	request, err := client.V2().UpdateBranchRequest(branchName, nil, annotations)
	assert.NoError(t, err)
	assert.Equal(t, "application/json", request.Header.Get("Content-Type"))
	assert.Equal(t, v2APIHeaderBeta, request.Header.Get(v2APIOutgoingHeaderID))
	assert.Equal(t, "localhost/branches/"+account+"/"+branchName, request.URL.Path)
	assert.Equal(t, http.MethodPatch, request.Method)

	// A nil owner is omitted; SaaS rejects any field but annotations with 422.
	bodyBytes, _ := io.ReadAll(request.Body)
	var sent map[string]interface{}
	assert.NoError(t, json.Unmarshal(bodyBytes, &sent))
	_, hasOwner := sent["owner"]
	assert.False(t, hasOwner, "UpdateBranchRequest must not send a nil owner")

	ownerReq, err := client.V2().UpdateBranchRequest(branchName, &Owner{Kind: "user", Id: "user1"}, nil)
	assert.NoError(t, err)
	ownerBody, _ := io.ReadAll(ownerReq.Body)
	assert.JSONEq(t, `{"owner":{"kind":"user","id":"user1"}}`, string(ownerBody))

	// A nil map must omit the field, not send "annotations":null.
	nilReq, err := client.V2().UpdateBranchRequest(branchName, nil, nil)
	assert.NoError(t, err)
	nilBody, _ := io.ReadAll(nilReq.Body)
	assert.NotContains(t, string(nilBody), "null")
}

func TestBranchIdentifier_RejectsTraversal(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, _ := NewClientFromJwt(config)

	for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
		_, err := client.V2().ReadBranchRequest(bad)
		assert.Errorf(t, err, "ReadBranchRequest(%q) must reject traversal", bad)

		_, err = client.V2().DeleteBranchRequest(bad)
		assert.Errorf(t, err, "DeleteBranchRequest(%q) must reject traversal", bad)
	}
}

func TestClientV2_DeleteBranchRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	ident := "super/hiper/test/id"
	client.config.Account = testAccount

	request, err := client.V2().DeleteBranchRequest(ident)
	assert.NoError(t, err)
	assert.Equal(t, v2APIHeaderBeta, request.Header.Get(v2APIOutgoingHeaderID))
	assert.Equal(t, "localhost/branches/"+testAccount+"/"+ident, request.URL.Path)
	assert.Equal(t, http.MethodDelete, request.Method)
}

func TestBranchIdentifier(t *testing.T) {
	assert.Equal(t, "data/prod", Branch{Name: "prod", Branch: "data"}.identifier())
	// Empty parent Branch: Name is assumed to already be a full identifier.
	assert.Equal(t, "data/prod", Branch{Name: "data/prod"}.identifier())
}

// newBranchErrorServer logs the client in like NewHandler and answers every
// other request with status and body.
func newBranchErrorServer(t *testing.T, status int, body string) *httptest.Server {
	login := NewHandler(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" || r.URL.Path == "/authn-jwt/jwt_service/account/authenticate" {
			login.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

// The Secrets Manager SaaS errors a CLI has to tell apart. A delete is never
// refused because the branch holds resources; it removes them all.
func TestClientV2_BranchErrors(t *testing.T) {
	deleteBranch := func(c *ClientV2) error { return c.DeleteBranch("data/app") }
	testCases := []struct {
		name    string
		call    func(c *ClientV2) error
		status  int
		message string
	}{
		{
			name: "Creating a branch that exists is a conflict",
			call: func(c *ClientV2) error {
				_, err := c.CreateBranch(Branch{Branch: "data", Name: "app"})
				return err
			},
			status:  http.StatusConflict,
			message: "Branch 'data/app' already exists",
		},
		{
			name:    "Deleting needs update on every branch under it",
			call:    deleteBranch,
			status:  http.StatusForbidden,
			message: "CONJ00161E Unable to preform the requested delete operation. Reason: Insufficient update permissions to delete resources under branch 'conjur:policy:data/app/db",
		},
		{
			name:    "Deleting what an admin created needs an admin",
			call:    deleteBranch,
			status:  http.StatusForbidden,
			message: "CONJ00161E Unable to preform the requested delete operation. Reason: Cannot Delete system resource 'conjur:variable:data/app/db/password'",
		},
		{
			name:    "The data branch can't be deleted",
			call:    func(c *ClientV2) error { return c.DeleteBranch("data") },
			status:  http.StatusForbidden,
			message: "CONJ00019E You cannot operate on a protected branch: 'data'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"error": map[string]string{"code": "x", "message": tc.message}})
			require.NoError(t, err)
			server := newBranchErrorServer(t, tc.status, string(body))
			defer server.Close()
			client, err := NewClientFromJwt(GetConfigForTest(server.URL))
			require.NoError(t, err)

			err = tc.call(client.V2())
			var conjurErr *response.ConjurError
			require.ErrorAs(t, err, &conjurErr)
			assert.Equal(t, tc.status, conjurErr.Code)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}
