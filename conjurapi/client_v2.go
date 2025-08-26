package conjurapi

// The V2Client struct is a sub-client for interacting with the v2 APIs in Conjur, which
// are not supported in all versions.
type V2Client struct {
	*Client
}
