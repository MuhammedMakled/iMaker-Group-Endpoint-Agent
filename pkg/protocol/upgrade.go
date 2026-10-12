package protocol

// MethodAgentUpgrade starts a remote self-update. It is a privileged method:
// the caller needs an elevated Windows admin token AND a global-admin session,
// which travels in the RPC envelope's auth field like every other privileged call.
const MethodAgentUpgrade = "agent.upgrade"

// UpgradeAgentParams are the upgrade-agent arguments. The admin credential is
// deliberately not a parameter: it is carried in the envelope's auth field so
// it is never logged as part of a request body.
type UpgradeAgentParams struct {
	DownloadURL   string `json:"download_url"`
	TargetVersion string `json:"target_version"`
	SHA256        string `json:"sha256_hash"`
}

// UpgradeAgentResult acknowledges that the upgrade was accepted. The outcome
// (UPGRADE_SUCCESS or UPGRADE_FAILED) is reported to the IT Command Center
// after the service restarts.
type UpgradeAgentResult struct {
	Status        string `json:"status"` // UPGRADE_ACCEPTED
	FromVersion   string `json:"from_version"`
	TargetVersion string `json:"target_version"`
}
