package matcher

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/armon/go-radix"
	"github.com/bits-and-blooms/bloom/v3"
)

const (
	RExact ruleType = iota
	RWildcard
)

func normalizeDomain(d string) (string, string) {
	d = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(d), "."))
	puny, _ := idna.Lookup.ToASCII(d)
	etld1, _ := publicsuffix.EffectiveTLDPlusOne(puny)
	return puny, etld1
}

func reverseLabels(d string) string {
	parts := strings.Split(d, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func BuildMatcher(rules []string) *Matcher {
	m := &Matcher{
		exact: make(map[string]struct{}, len(rules)),
		wild:  radix.New(),
	}

	if len(rules) > 10000 {
		m.bf = bloom.NewWithEstimates(uint(len(rules))*4, 1e-4)
	}

	for _, raw := range rules {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}

		// Check for match-all wildcard
		if r == "*" {
			m.matchAll = true
			continue
		}

		isWildcard := strings.HasPrefix(r, "*.")
		base := r
		if isWildcard {
			base = strings.TrimPrefix(r, "*.")
		}

		canon, _ := normalizeDomain(base)
		if canon == "" {
			continue
		}

		if isWildcard {
			key := reverseLabels(canon)
			m.wild.Insert(key, &rule{typ: RWildcard, val: canon})
			if m.bf != nil {
				m.bf.AddString(canon)
			}
		} else {
			m.exact[canon] = struct{}{}
			if m.bf != nil {
				m.bf.AddString(canon)
			}
		}
	}
	return m
}

func (m *Matcher) Match(query string) MatchResult {
	q, _ := normalizeDomain(query)
	if q == "" {
		return MatchResult{}
	}

	// Check match-all flag first
	if m.matchAll {
		return MatchResult{Matched: true, Rule: "*", Type: RWildcard}
	}

	if m.bf != nil && !m.bf.TestString(q) {
		// Bloom filter optimization
	}

	if _, ok := m.exact[q]; ok {
		return MatchResult{Matched: true, Rule: q, Type: RExact}
	}

	rev := reverseLabels(q)
	parts := strings.Split(rev, ".")
	var best *rule
	var bestLen int

	for i := 1; i <= len(parts); i++ {
		prefix := strings.Join(parts[:i], ".")
		if v, ok := m.wild.Get(prefix); ok {
			r := v.(*rule)
			qLabels := strings.Count(q, ".") + 1
			rLabels := strings.Count(r.val, ".") + 1
			if qLabels > rLabels {
				if len(prefix) > bestLen {
					best = r
					bestLen = len(prefix)
				}
			}
		}
	}

	if best != nil {
		return MatchResult{Matched: true, Rule: "*." + best.val, Type: RWildcard}
	}

	return MatchResult{}
}
