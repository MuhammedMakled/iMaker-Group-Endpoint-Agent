package tracker

import (
	"net"
	"net/url"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// BrowserFilter applies the privacy rules for browser activity:
//
//   - Only the domain is ever recorded — never the URL path, query string or
//     page title.
//   - Private / Incognito / InPrivate windows are ignored entirely.
//   - Personal domains (banking, personal e-mail, social) are recorded as
//     "Browser - Other" with no domain.
//   - Work domains (allow-list) are recorded as "Browser - Work" with domain.
//   - Anything else is "Browser - Other"; its domain is kept only when
//     RecordUnlistedDomains is enabled.
//
// Domain source: browser window titles do not contain the URL, so a real
// domain requires a DomainProvider (see tracker.go). Without one, the filter
// falls back to configurable title keywords, which is privacy-safe but coarse.
type BrowserFilter struct {
	WorkDomains           []string
	PersonalDomains       []string
	WorkTitleKeywords     map[string]string
	PersonalTitleKeywords []string
	RecordUnlistedDomains bool
}

// BrowserVerdict is the privacy-filtered result for one browser sample.
type BrowserVerdict struct {
	Category string
	Domain   string
	Private  bool
}

var privateMarkers = []string{
	"inprivate",        // Edge
	"private browsing", // Firefox
	"incognito",        // Chrome (when exposed by title/extension)
	"private window",   // Brave / Opera
}

// IsPrivateTitle reports whether a browser window title indicates a private session.
func IsPrivateTitle(title string) bool {
	t := strings.ToLower(title)
	for _, m := range privateMarkers {
		if strings.Contains(t, m) {
			return true
		}
	}
	return false
}

// Classify applies the rules above. title is inspected in memory only.
func (f *BrowserFilter) Classify(title, domainHint string) BrowserVerdict {
	if IsPrivateTitle(title) {
		return BrowserVerdict{Private: true}
	}
	if d := NormalizeDomain(domainHint); d != "" {
		switch {
		case matchDomain(d, f.PersonalDomains):
			return BrowserVerdict{Category: protocol.CategoryBrowserOther}
		case matchDomain(d, f.WorkDomains):
			return BrowserVerdict{Category: protocol.CategoryBrowserWork, Domain: d}
		case f.RecordUnlistedDomains:
			return BrowserVerdict{Category: protocol.CategoryBrowserOther, Domain: d}
		default:
			return BrowserVerdict{Category: protocol.CategoryBrowserOther}
		}
	}
	// Title-keyword fallback. Personal keywords win over work keywords.
	lt := strings.ToLower(title)
	for _, k := range f.PersonalTitleKeywords {
		if k != "" && strings.Contains(lt, strings.ToLower(k)) {
			return BrowserVerdict{Category: protocol.CategoryBrowserOther}
		}
	}
	for k, label := range f.WorkTitleKeywords {
		if k != "" && strings.Contains(lt, strings.ToLower(k)) {
			return BrowserVerdict{Category: protocol.CategoryBrowserWork, Domain: label}
		}
	}
	return BrowserVerdict{Category: protocol.CategoryBrowserOther}
}

// NormalizeDomain reduces a URL or host to a bare lower-case host name,
// stripping scheme, credentials, port, path, query, fragment and "www.".
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "www."), ".")
	if host == "" || strings.ContainsAny(host, " /") {
		return ""
	}
	return host
}

// matchDomain reports whether d equals or is a subdomain of any entry.
func matchDomain(d string, list []string) bool {
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if d == e || strings.HasSuffix(d, "."+e) {
			return true
		}
	}
	return false
}
