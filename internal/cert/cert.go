// Package cert loads the certificates named in the config (ADR 0004, file source in v0).
package cert

import (
	"crypto/tls"
	"errors"
	"fmt"
	"slices"

	"github.com/scorsi/genkan/internal/config"
)

// Files is the loaded [certificates.<name>] set.
type Files map[string]*tls.Certificate

// Load reads every pair; the error joins every pair that failed.
func Load(cfg map[string]config.Certificate) (Files, error) {
	files := Files{}
	var errs []error
	for _, name := range slices.Sorted(keys(cfg)) {
		c, err := tls.LoadX509KeyPair(cfg[name].Cert, cfg[name].Key)
		if err != nil {
			errs = append(errs, fmt.Errorf("certificates.%s: %w", name, err))
			continue
		}
		files[name] = &c
	}
	return files, errors.Join(errs...)
}

// Covers reports whether the named certificate's SANs include host.
func (f Files) Covers(name, host string) bool {
	c := f[name]
	return c != nil && c.Leaf != nil && c.Leaf.VerifyHostname(host) == nil
}

func keys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
