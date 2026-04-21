package conjurapi

const MinVersion = "1.23.0"
const NotSupportedInConjurCloud = "%s is not supported in Idira Secrets Manager, SaaS"
const NotSupportedInConjurEnterprise = "%s is not supported in Idira Secrets Manager/Conjur OSS"
const NotSupportedInOldVersions = "%s is not supported in Idira Secrets Manager versions older than %s"

type ClientV2 struct {
	*Client
}
