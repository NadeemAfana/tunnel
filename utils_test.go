package main

import (
	"net/url"
	"testing"
)

func TestTunnelNameValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// "should invalidate empty subdomain"
		{"empty", "", false},
		{"whitespace only", "   ", false},
		// "should validate subdomains"
		{"valid alphanumeric", "abcd", true},
		{"valid with single dash", "my-sub", true},
		// "should invalidate multiple consecutive dashes"
		{"consecutive dashes", "a--c", false},
		{"consecutive dashes mid-name", "abc-d--r", false},
		// "should validate multiple separate dashes"
		{"separate dashes", "a-b-c", true},
		{"separate dashes longer", "abc-d-r", true},
		// "should invalidate subdomains with invalid chars"
		{"asterisk", "a*bcd", false},
		{"dot", "dsdsfs.fsdfd", false},
		// "should invalidate subdomains beginning or ending with a dash"
		{"leading dash", "-a-b-c", false},
		{"trailing dash", "abc-d-r-", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tunnelNameValid(tt.input); got != tt.want {
				t.Errorf("tunnelNameValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		domain  string
		want    string
		wantErr bool
	}{
		// "should error on empty subdomain" — original passes the package-level
		// domainURL which is "" at test time (no main() ran), so we mirror that.
		{"empty host", "", "", "", true},
		// "should extract subdomain"
		{"basic subdomain", "abc.domain.io", "domain.io", "abc", false},
		{"hyphenated subdomain", "open-idc.domain.io", "domain.io", "open-idc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractSubdomain(tt.host, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractSubdomain(%q, %q) err=%v, wantErr=%v", tt.host, tt.domain, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.want)
			}
		})
	}
}

func TestExtractTunnelNameFromURLPath(t *testing.T) {
	tests := []struct {
		name      string
		domainURL string
		path      string
		want      string
		wantErr   bool
	}{
		// "should error when tunnelName not found in domainURL"
		{"name not in domain (slash)", "http://domain.io/x/y/z", "/a/y/z/tunnel/c", "", true},
		{"name not in domain (no slash)", "http://domain.io/x/y/z", "a/y/z/tunnel/c", "", true},
		// "should extract tunnelName when domainURL has path"
		{"matches with domain path (slash)", "http://domain.io/x/y/z", "/x/y/z/tunnel/c", "tunnel", false},
		{"matches with domain path (no slash)", "http://domain.io/x/y/z", "x/y/z/tunnel/c", "tunnel", false},
		// "should extract tunnelName when domainURL has no path"
		{"no domain path (slash)", "https://domain.io", "/x/y/z/tunnel", "x", false},
		{"no domain path (no slash)", "https://domain.io", "x/y/z/tunnel", "x", false},
		// "should extract tunnelName when domainURL has empty path"
		{"empty domain path (slash)", "https://domain.io/", "/x/y/z/tunnel", "x", false},
		{"empty domain path (no slash)", "https://domain.io/", "x/y/z/tunnel", "x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.domainURL)
			if err != nil {
				t.Fatalf("parse domain url %q: %v", tt.domainURL, err)
			}
			got, err := extractTunnelNameFromURLPath(tt.path, *u)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReplaceRequestURL(t *testing.T) {
	newDomainLocalhost := "localhost"
	newDomain456 := "newdomain:456"

	tests := []struct {
		name            string
		requestURL      string
		newHost         *string
		stripPrefixPath string
		want            string
		wantErr         bool
	}{
		// "should replace request URL when requestURL has a relative path"
		{"relative path no host (slash prefix)", "/x/y/z/tunnel/c", nil, "/x/y/z/tunnel", "/c", false},
		{"relative path no host (no slash prefix)", "/x/y/z/tunnel/c", nil, "x/y/z/tunnel", "/c", false},
		{"relative path with host", "/x/y/z/tunnel/c", &newDomainLocalhost, "/x/y/z/tunnel", "/c", false},
		// "should replace request URL when requestURL has an absolute path"
		{"absolute path no host (slash prefix)", "https://localhost:123/x/y/z/tunnel/c", nil, "/x/y/z/tunnel", "https://localhost:123/c", false},
		{"absolute path no host (no slash prefix)", "https://localhost:123/x/y/z/tunnel/c", nil, "x/y/z/tunnel", "https://localhost:123/c", false},
		{"absolute path with new host", "https://localhost:123/x/y/z/tunnel/c", &newDomain456, "/x/y/z/tunnel", "https://newdomain:456/c", false},
		// "should replace request URL when requestURL has an absolute path without prefix path"
		{"absolute path empty prefix", "https://localhost:123/x/y/z/tunnel/c", nil, "", "https://localhost:123/x/y/z/tunnel/c", false},
		{"absolute path slash prefix", "https://localhost:123/x/y/z/tunnel/c", nil, "/", "https://localhost:123/x/y/z/tunnel/c", false},
		{"absolute path new host empty prefix", "https://localhost:123/x/y/z/tunnel/c", &newDomain456, "", "https://newdomain:456/x/y/z/tunnel/c", false},
		// "should replace request URL when requestURL has an empty path"
		{"empty request path slash prefix", "/", nil, "/", "/", false},
		{"empty request path empty prefix", "/", nil, "", "/", false},
		// "should replace request URL when requestURL has relative path and prefix has different path"
		{"prefix mismatch", "/relative", nil, "/path", "/relative", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := replaceRequestURL(tt.requestURL, tt.newHost, tt.stripPrefixPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("replaceRequestURL(%q, %v, %q) = %q, want %q", tt.requestURL, tt.newHost, tt.stripPrefixPath, got, tt.want)
			}
		})
	}
}
