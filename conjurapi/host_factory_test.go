package conjurapi

import (
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestClient_Token(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	login := os.Getenv("CONJUR_AUTHN_LOGIN")
	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	var token string

	testCases := []struct {
		name          string
		duration      string
		hostFactory   string
		count         int
		cidr          []string
		expectNoToken bool
		assert        func(*testing.T, error)
		assertHost    func(*testing.T, int, error)
	}{
		{
			name:        "Create a token",
			duration:    "10m",
			hostFactory: "cucumber:host_factory:factory",
			count:       1,
			cidr:        []string{"0.0.0.0/0"},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				assert.NoError(t, err)
				assert.True(t, size > 0)
			},
		},
		{
			name:        "Create a token with two cidrs",
			duration:    "10m",
			hostFactory: "cucumber:host_factory:factory",
			count:       1,
			cidr:        []string{"0.0.0.0/0", "0.0.0.0/32"},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				assert.NoError(t, err)
				assert.True(t, size > 0)
			},
		},
		{
			name:        "Create a token with empty cidrs",
			duration:    "10m",
			hostFactory: "cucumber:host_factory:factory",
			count:       1,
			cidr:        []string{},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				assert.NoError(t, err)
				assert.True(t, size > 0)
			},
		},
		{
			name:        "Create Two tokens",
			duration:    "10m",
			hostFactory: "cucumber:host_factory:factory",
			count:       2,
			cidr:        []string{"0.0.0.0/0", "0.0.0.0/32"},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				assert.NoError(t, err)
				assert.True(t, size > 0)
			},
		},
		{
			name:        "Create a token with invalid cidr",
			duration:    "10m",
			hostFactory: "cucumber:host_factory:factory",
			count:       1,
			cidr:        []string{"127.0.0.1"},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:          "Invalid duration",
			duration:      "10",
			hostFactory:   "cucumber:host_factory:factory",
			count:         1,
			cidr:          []string{"0.0.0.0/0"},
			expectNoToken: true,
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
			assertHost: func(t *testing.T, size int, err error) {
				return
			},
		},
	}

	t.Run("Host Factory", func(t *testing.T) {
		identifier := "factory"
		policy := fmt.Sprintf(`- !layer lay
- !host-factory
  id: %s
  layers: [!layer lay]`, identifier)
		conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
		assert.NoError(t, err)

		conjur.LoadPolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)
		for _, tc := range testCases {
			token = ""
			t.Run(tc.name, func(t *testing.T) {
				tokens, err := conjur.CreateToken(tc.duration, tc.hostFactory, tc.cidr, tc.count)
				tc.assert(t, err)
				if err == nil {
					assert.Equal(t, len(tokens), tc.count)
					for _, tokn := range tokens {
						// We just save one token if there are multiple
						token = tokn.Token
						assert.True(t, len(token) > 0)
					}
				}
			})
			if tc.expectNoToken == true {
				continue
			}
			t.Run("Create Host", func(t *testing.T) {
				data := url.Values{}
				data.Set("id", "new-host")
				host, err := conjur.CreateHost(data, token)
				tc.assertHost(t, len(host.ApiKey),err)
			})
			t.Run("Delete Token", func(t *testing.T) {
				err := conjur.DeleteToken(token)
				assert.NoError(t, err)
			})
		}
	})
}
