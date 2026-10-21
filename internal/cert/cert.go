// Package cert loads the certificates named in the config (ADR 0004, file source in v0).
package cert

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/scorsi/genkan/internal/config"
)

// Files is the loaded [certificates.<name>] set.
type Files map[string]*tls.Certificate

// Load reads every pair. A pair that is not ready, a file missing or the key not matching the
// certificate (hanko has not issued it yet, or is between its two renames), keeps its pair from
// prev or is left out, and is reported in notReady by name. Any other failure is an error, joined
// over every pair that failed (ADR 0004, ADR 0009).
func Load(cfg map[string]config.Certificate, prev Files) (files Files, notReady map[string]error, err error) {
	files, notReady = Files{}, map[string]error{}
	var errs []error
	for _, name := range slices.Sorted(keys(cfg)) {
		c, err := tls.LoadX509KeyPair(cfg[name].Cert, cfg[name].Key)
		switch {
		case err == nil:
			files[name] = &c
		// crypto/tls has no sentinel for a mismatch; TestCertificateNotReady catches a rewording.
		case errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "does not match"):
			notReady[name] = err
			if prev[name] != nil {
				files[name] = prev[name]
			}
		default:
			errs = append(errs, fmt.Errorf("certificates.%s: %w", name, err))
		}
	}
	return files, notReady, errors.Join(errs...)
}

// Covers reports whether the named certificate's SANs include host.
func (f Files) Covers(name, host string) bool {
	c := f[name]
	return c != nil && c.Leaf != nil && c.Leaf.VerifyHostname(host) == nil
}

// Expiry is each certificate's leaf NotAfter in Unix seconds.
func (f Files) Expiry() map[string]int64 {
	m := map[string]int64{}
	for name, c := range f {
		if c.Leaf != nil {
			m[name] = c.Leaf.NotAfter.Unix()
		}
	}
	return m
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
