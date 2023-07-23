package main

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
)

// subDomainValid returns true if subdomain name is valid
func subDomainValid(subdomain string) bool {
	subdomainValid := len(subdomain) < 50

	if subdomain == "" || !subdomainValid {
		return false
	}
	subdomain = strings.ToLower(subdomain)
	if subdomain[0] == '-' || subdomain[len(subdomain)-1] == '-' {
		subdomainValid = false
	}

	if subdomainValid {
		for i := 0; i < len(subdomain); i++ {
			if (subdomain[i] >= 'a' && subdomain[i] <= 'z') ||
				(subdomain[i] >= '0' && subdomain[i] <= '9') ||
				subdomain[i] == '-' {

				// No consecutive dashes
				if subdomain[i] == '-' && i+1 < len(subdomain) && subdomain[i+1] == '-' {
					subdomainValid = false
					break
				}
				continue
			} else {
				subdomainValid = false
				break
			}
		}
	}

	return subdomainValid
}

// Returns subdomain if found from host name, or domain, or an empty string
// host must be valid
func extractSubdomain(host string) (string, error) {
	domainIndex := strings.Index(host, domain)
	if domainIndex <= 0 {
		return "", errors.New("could not find a valid subdomain in http request headers")
	}
	return strings.TrimSpace(host[:domainIndex-1]), nil
}

const subDomainLength = 4

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

func generateRandomSubdomain() (string, error) {

	// As an alternative to this method, base64 can be used but both the padding and invalid characters
	// must be removed (ie / and =).
	randomBytes := make([]byte, subDomainLength)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}

	subDomain := make([]rune, subDomainLength)

	for i, b := range randomBytes {
		subDomain[i] = charMap[(int)(b)%36]
	}

	return string(subDomain), nil
}
