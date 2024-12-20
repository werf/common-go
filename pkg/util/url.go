package util

import (
	"fmt"
	"net/url"
)

// UrlParseHostPort return host:port from given string
func UrlParseHostPort(rawurl string) (string, error) {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return "", fmt.Errorf("can't parse server address: %w", err)
	}
	return parsedURL.Host, nil
}
