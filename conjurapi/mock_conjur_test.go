package conjurapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Creates a Conjur client that points towards a mock Conjur server.
// The server will return test values for the login, authenticate, and OIDC provider endpoints,
// as well as for the /info and / endpoints.
// TODO: Use actual Conjur instance instead of mock server?
func createMockConjurClient(t *testing.T) (*httptest.Server, *Client) {
	mockConjurServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Listen for the login, authenticate, and oidc endpoints and return test values
		if strings.HasSuffix(r.URL.Path, "/authn/conjur/login") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-api-key"))
		} else if strings.HasSuffix(r.URL.Path, "/authn/conjur/alice/authenticate") {
			// Ensure that the api key we returned in /login is being used
			body, _ := io.ReadAll(r.Body)
			if string(body) == "test-api-key" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test-token"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else if strings.HasSuffix(r.URL.Path, "/authn-oidc/test-service-id/conjur/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-token-oidc"))
		} else if strings.HasSuffix(r.URL.Path, "/authn-jwt/test-service-id/conjur/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-token-jwt"))
		} else if strings.HasSuffix(r.URL.Path, "/authn-oidc/conjur/providers") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"service_id": "test-service-id"}]`))
		} else if r.URL.Path == "/info" {
			if mockEnterpriseInfo == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockEnterpriseInfo))
		} else if r.URL.Path == "/" {
			w.Header().Set("Content-Type", mockRootResponseContentType)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockRootResponse))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	tempDir := t.TempDir()
	config := Config{
		Account:           "conjur",
		ApplianceURL:      mockConjurServer.URL,
		NetRCPath:         filepath.Join(tempDir, ".netrc"),
		CredentialStorage: "file",
	}
	storage, _ := createStorageProvider(config)
	client := &Client{
		config:     config,
		httpClient: &http.Client{},
		storage:    storage,
	}

	return mockConjurServer, client
}

var mockEnterpriseInfo = `{
  "release": "13.5.0",
  "version": "5.19.0-9",
  "services": {
    "ldap-sync": {
      "desired": "i",
      "status": "i",
      "err": null,
      "description": "Conjur",
      "name": "conjur-ldap-sync",
      "version": "2.4.9-452",
      "arch": "amd64"
    },
    "possum": {
      "desired": "i",
      "status": "i",
      "err": null,
      "description": "Conjur",
      "name": "conjur-possum",
      "version": "1.21.3-11",
      "arch": "amd64"
    },
    "ui": {
      "desired": "i",
      "status": "i",
      "err": null,
      "description": "Conjur",
      "name": "conjur-ui",
      "version": "2.18.0-512",
      "arch": "amd64"
    }
  },
  "container": "conjur-leader-1.mycompany.local",
  "role": "master",
  "configuration": {
    "conjur": {
      "account": "conjur",
      "altnames": [
        "AMPM-42529A0948.ampm.cyberng.com",
        "localhost",
        "conjur-leader.mycompany.local",
        "conjur-leader-1.mycompany.local",
        "conjur-leader-2.mycompany.local",
        "conjur-leader-3.mycompany.local",
        "AMPM-42529A0948.ampm.cyberng.com"
      ],
      "hostname": "AMPM-42529A0948.ampm.cyberng.com",
      "master_altnames": [
        "AMPM-42529A0948.ampm.cyberng.com",
        "localhost",
        "conjur-leader.mycompany.local",
        "conjur-leader-1.mycompany.local",
        "conjur-leader-2.mycompany.local",
        "conjur-leader-3.mycompany.local",
        "AMPM-42529A0948.ampm.cyberng.com"
      ],
      "role": "master"
    }
  },
  "authenticators": {
    "error": "Conjur service not available."
  },
  "fips_mode": "enabled",
  "feature_flags": {
    "selective_replication": "enabled"
  }
}`

var mockRootResponseHTML = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">

    <link rel="stylesheet" href="/css/status-page.css">
    <title>Conjur Status</title>
  </head>
  <body>

    <header>
      <div class="logo-cont">
        <img src="/img/conjur-logo-all-white.svg"/>
      </div>
      <div class="links-cont">
        <a href="https://discuss.cyberarkcommons.org" target="_blank">Discourse</a>
        |
        <a href="https://github.com/cyberark/conjur" target="_blank">Github</a>
      </div>
    </header>

    <main>
      <div class="left-panel">
        <h1>Status</h1>
        <p class="status-text">Your Conjur server is running!</p>

        <h2>Security Check:</h2>
        <p>Does your browser show a green lock icon on the left side of the address bar?</p>

        <dl>
          <dt>Green lock:</dt>
          <dd>Good, Conjur is secured and authenticated.</dd>
          <dt>Yellow lock or green with warning sign:</dt>
          <dd>
          OK, Conjur is secured but not authenticated. Send your Conjur admin to the
          <a href="https://www.conjur.org/tutorials/nginx.html" title="Tutorial - NGINX Proxy">
            Conjur+TLS guide
          </a>
          to learn how to use your own certificate &amp; upgrade to green lock.
          </dd>
          <dt>Red broken lock or no lock:</dt>
          <dd>
          Conjur is running in insecure development mode. Don't put any
          production secrets in there! Visit the
          <a href="https://www.conjur.org/tutorials/nginx.html" title="Tutorial - NGINX Proxy">
            Conjur+TLS guide
          </a>
          to learn how to deploy Conjur securely &amp;
          <a href="https://discuss.cyberarkcommons.org">contact CyberArk</a>
          with any questions.
          </dd>
        </dl>
      </div>

      <div class="right-panel">
        <dl>
          <dt>Details:</dt>
          <dd>Version 0.0.dev</dd>
          <dd>API Version <a href="https://github.com/cyberark/conjur-openapi-spec/releases/tag/v5.3.1
">5.3.1
</a>
          <dd>FIPS mode enabled</a>
          <dt>More Info:</dt>
          <dd>
            <ul>
              <li><a href="https://docs.conjur.org/Latest/en/Content/Resources/_TopNav/cc_Home.htm" target="_blank">Documentation</a></li>
              <li><a href="https://www.cyberark.com/products/privileged-account-security-solution/application-access-manager/" target="_blank">CyberArk Application Access Manager</a></li>
              <li><a href="https://www.conjur.org/" target="_blank">Conjur.org</a></li>
            </ul>
          </dd>
        </dl>

      </div>
    </main>

    <footer>
      <div class="logo-cont">
        <img src="/img/cyberark-white.png"/>
      </div>
      <p class="copyright">
        Conjur Open Source copyright 2020 CyberArk. All rights reserved.
      </p>
    </footer>

  </body>
</html>`

var mockRootResponseJSON = `{"version": "0.0.dev"}`

var mockRootResponse = mockRootResponseHTML
var mockRootResponseContentType = "text/html"
