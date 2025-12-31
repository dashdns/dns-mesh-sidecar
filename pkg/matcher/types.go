package matcher

import (
	"sync/atomic"

	"github.com/armon/go-radix"
	"github.com/bits-and-blooms/bloom/v3"
)

type ruleType uint8

type rule struct {
	typ ruleType
	val string
}

type Matcher struct {
	exact    map[string]struct{}
	wild     *radix.Tree
	bf       *bloom.BloomFilter
	matchAll bool
}

type AtomicMatcher struct {
	Ptr atomic.Pointer[Matcher]
}

type MatchResult struct {
	Matched bool
	Rule    string
	Type    ruleType
}
