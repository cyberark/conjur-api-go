package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientV2_SWA_NotSaaS(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	require.NoError(t, err)

	_, err = client.V2().SWA()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SWA API")
	assert.Contains(t, err.Error(), "not supported in Idira Secrets Manager/Conjur OSS")
}
