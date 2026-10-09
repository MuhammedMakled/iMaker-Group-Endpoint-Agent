param(
    [string]$Version = "1.0.0-dev",
    [string]$Out = "dist"
)
$ErrorActionPreference = "Stop"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$ld = "-s -w -X github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config.Version=$Version"

go mod tidy
go vet ./...
go test ./...

New-Item -ItemType Directory -Force -Path $Out | Out-Null
go build -trimpath -ldflags "$ld -H=windowsgui" -o "$Out\ImakerTrayApp.exe" ./cmd/agent
go build -trimpath -ldflags "$ld" -o "$Out\ImakerAgentService.exe" ./cmd/service

# Optional: sign
# signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "$Out\*.exe"

Get-ChildItem $Out | Format-Table Name, Length
