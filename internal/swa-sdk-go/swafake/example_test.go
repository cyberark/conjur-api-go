package swafake_test

import (
	"context"
	"fmt"

	swa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake"
)

// Example shows how a consumer can test code that talks to the SWA API
// without a real backend: start a fake, hand its Client to the code
// under test, and assert on the result.
func Example() {
	fake := swafake.New(swafake.WithTrustDomain("prod.example.com"))
	defer fake.Close()

	client := fake.Client()

	sg, action, err := client.ServerGroups().Apply(context.Background(), "prod.example.com", swa.CreateServerGroupRequest{
		Name: "web",
		Attestation: &swa.AttestationConfiguration{
			GcpServiceAccount: &swa.GcpServiceAccountAttestationConfiguration{
				AllowedProjectIds: []string{"proj-1"},
			},
		},
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(action, sg.Name)
	fmt.Println("audiences:", (*sg.Attestation.GcpServiceAccount.Audiences)[0])
	// Output:
	// created web
	// audiences: urn:panw:swa
}
