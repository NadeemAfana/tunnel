package main

import (
	"crypto/rand"
	"errors"
	"io"
	"net/url"
	"strings"
)

// tunnelNameValid returns true if tunnelName is valid
func tunnelNameValid(tunnelName string) bool {
	nameValid := len(tunnelName) < 50

	if tunnelName == "" || !nameValid {
		return false
	}
	tunnelName = strings.ToLower(tunnelName)
	if tunnelName[0] == '-' || tunnelName[len(tunnelName)-1] == '-' {
		nameValid = false
	}

	if nameValid {
		for i := 0; i < len(tunnelName); i++ {
			if (tunnelName[i] >= 'a' && tunnelName[i] <= 'z') ||
				(tunnelName[i] >= '0' && tunnelName[i] <= '9') ||
				tunnelName[i] == '-' {

				// No consecutive dashes
				if tunnelName[i] == '-' && i+1 < len(tunnelName) && tunnelName[i+1] == '-' {
					nameValid = false
					break
				}
				continue
			} else {
				nameValid = false
				break
			}
		}
	}

	return nameValid
}

// Returns subdomain if found from host name, or domain, or an empty string
// host must be valid.
func extractSubdomain(host string, domainHost string) (string, error) {
	// Find domain in host
	domainIndex := strings.Index(host, domainHost)
	if domainIndex <= 0 {
		return "", errors.New("could not find a valid subdomain in http request headers")
	}
	return strings.TrimSpace(host[:domainIndex-1]), nil
}

// replaceRequestURL returns a new URL replacing requestURL with newHost and newURLPath.
// If requestURL is absolute, then it replaces its domain with newHost if newHost is specified.
// If stripPrefixPath is specified (not empty), then the final url path will have stripPrefixPath stripped (left trimmed).
func replaceRequestURL(requestURL string, newHost *string, stripPrefixPath string) (string, error) {

	requestUri, err := url.ParseRequestURI(requestURL)
	if err != nil {
		return requestURL, err
	}

	replacedURL, _ := url.ParseRequestURI(requestURL)

	if requestUri.IsAbs() && newHost != nil {
		// Replace domain
		replacedURL.Host = *newHost
	}

	if stripPrefixPath != "" {
		var path string = requestUri.Path
		var pathPrefix string = stripPrefixPath
		if strings.HasPrefix(requestUri.Path, "/") {
			// Skip leading /
			path = requestUri.Path[1:]
		}
		if strings.HasPrefix(stripPrefixPath, "/") {
			// Skip leading /
			pathPrefix = stripPrefixPath[1:]
		}

		skipped := strings.TrimPrefix(path, pathPrefix)
		replacedURL.Path = skipped
	}

	// Ensure path starts with / if it is relative.
	if !replacedURL.IsAbs() && !strings.HasPrefix(replacedURL.Path, "/") {
		replacedURL.Path = "/" + replacedURL.Path
	}

	return replacedURL.String(), nil
}

// Returns tunnelName if found from http URL path or an empty string.
// path must be valid.
func extractTunnelNameFromURLPath(path string, domainURL url.URL) (string, error) {
	// Extract the first path after domainURL
	// if domainURL=domain.io and path=/ab/c/d then tunnelName is ab.
	// if domainURL=domain.io/ab/ and path=/ab/c/d then tunnelName is c.

	// Extract domain path from domainURL
	var domainPath string = domainURL.Path
	domainEndIndex := strings.Index(domainPath, "/")
	if domainEndIndex == -1 {
		// Ensure the domain path starts with / if path starts with /.
		if strings.HasPrefix(path, "/") {
			domainPath = "/"
		} else {
			domainPath = ""
		}
	} else {
		if strings.HasPrefix(path, "/") {
			domainPath = domainPath[domainEndIndex:]
		} else {
			domainPath = domainPath[domainEndIndex+1:]
		}
	}

	if !strings.HasPrefix(path, domainPath) {
		return "", errors.New("could not find a valid tunnelName in http request path")
	}

	trimmedPath := strings.TrimPrefix(path, domainPath)

	trimmedPath = strings.TrimPrefix(trimmedPath, "/")

	domainEndIndex = strings.Index(trimmedPath, "/")
	if domainEndIndex == -1 {
		domainEndIndex = len(trimmedPath)
	}

	tunnelName := strings.TrimSpace(trimmedPath[:domainEndIndex])
	if tunnelName == "" {
		return "", errors.New("could not find a valid tunnelName in http request path")
	}

	return tunnelName, nil
}

const tunnelNameLength = 4

var charMap map[int]rune

func init() {
	if charMap == nil {
		charMap = make(map[int]rune)
		for i := 0; i <= 9; i++ {
			charMap[i] = rune(i) + rune('0')
		}

		aCode := int('a')
		for i := 10; i <= 35; i++ {
			charMap[i] = rune(aCode + i - 10)
		}
	}
}

func generateRandomTunnelName() (string, error) {

	// As an alternative to this method, base64 can be used but both the padding and invalid characters
	// must be removed (ie / and =).
	randomBytes := make([]byte, tunnelNameLength)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}

	tunnelName := make([]rune, tunnelNameLength)

	for i, b := range randomBytes {
		tunnelName[i] = charMap[(int)(b)%36]
	}

	return string(tunnelName), nil
}
