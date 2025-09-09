package conjurapi

const MinVersion = "1.23.0"
const NotSupportedInConjurCloud = "%s is not supported in Conjur Cloud"
const NotSupportedInConjurEnterprise = "%s is not supported in Conjur Enterprise/OSS"
const NotSupportedInOldVersions = "%s is not supported in Conjur versions older than %s"

type ClientV2 struct {
	*Client
}
