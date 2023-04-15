package pattern

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var matcher = NewMatcher()

func TestMatches(t *testing.T) {
	// test exact matching
	assert.True(t, matcher.Matches("test", "test"))
	assert.True(t, matcher.Matches("/test", "/test"))
	assert.True(t, matcher.Matches("https://example.org", "https://example.org"))
	assert.False(t, matcher.Matches("/test.jpg", "test.jpg"))
	assert.False(t, matcher.Matches("test", "/test"))
	assert.False(t, matcher.Matches("/test", "test"))

	// test matching with ?'s
	assert.True(t, matcher.Matches("t?st", "test"))
	assert.True(t, matcher.Matches("??st", "test"))
	assert.True(t, matcher.Matches("tes?", "test"))
	assert.True(t, matcher.Matches("te??", "test"))
	assert.True(t, matcher.Matches("?es?", "test"))
	assert.False(t, matcher.Matches("tes?", "tes"))
	assert.False(t, matcher.Matches("tes?", "testt"))
	assert.False(t, matcher.Matches("tes?", "tsst"))

	// test matching with *'s
	assert.True(t, matcher.Matches("*", "test"))
	assert.True(t, matcher.Matches("test*", "test"))
	assert.True(t, matcher.Matches("test*", "testTest"))
	assert.True(t, matcher.Matches("test/*", "test/Test"))
	assert.True(t, matcher.Matches("test/*", "test/t"))
	assert.True(t, matcher.Matches("test/*", "test/"))
	assert.True(t, matcher.Matches("*test*", "AnothertestTest"))
	assert.True(t, matcher.Matches("*test", "Anothertest"))
	assert.True(t, matcher.Matches("*.*", "test."))
	assert.True(t, matcher.Matches("*.*", "test.test"))
	assert.True(t, matcher.Matches("*.*", "test.test.test"))
	assert.True(t, matcher.Matches("test*aaa", "testblaaaa"))
	assert.False(t, matcher.Matches("test*", "tst"))
	assert.False(t, matcher.Matches("test*", "tsttest"))
	assert.False(t, matcher.Matches("test*", "test/"))
	assert.False(t, matcher.Matches("test*", "test/t"))
	assert.False(t, matcher.Matches("test/*", "test"))
	assert.False(t, matcher.Matches("*test*", "tsttst"))
	assert.False(t, matcher.Matches("*test", "tsttst"))
	assert.False(t, matcher.Matches("*.*", "tsttst"))
	assert.False(t, matcher.Matches("test*aaa", "test"))
	assert.False(t, matcher.Matches("test*aaa", "testblaaab"))

	// test matching with ?'s and /'s
	assert.True(t, matcher.Matches("/?", "/a"))
	assert.True(t, matcher.Matches("/?/a", "/a/a"))
	assert.True(t, matcher.Matches("/a/?", "/a/b"))
	assert.True(t, matcher.Matches("/??/a", "/aa/a"))
	assert.True(t, matcher.Matches("/a/??", "/a/bb"))
	assert.True(t, matcher.Matches("/?", "/a"))

	// test matching with **'s
	assert.True(t, matcher.Matches("/**", "/testing/testing"))
	assert.True(t, matcher.Matches("/*/**", "/testing/testing"))
	assert.True(t, matcher.Matches("/**/*", "/testing/testing"))
	assert.True(t, matcher.Matches("/bla/**/bla", "/bla/testing/testing/bla"))
	assert.True(t, matcher.Matches("/bla/**/bla", "/bla/testing/testing/bla/bla"))
	assert.True(t, matcher.Matches("/**/test", "/bla/bla/test"))
	assert.True(t, matcher.Matches("/bla/**/**/bla", "/bla/bla/bla/bla/bla/bla"))
	assert.True(t, matcher.Matches("/bla*bla/test", "/blaXXXbla/test"))
	assert.True(t, matcher.Matches("/*bla/test", "/XXXbla/test"))
	assert.False(t, matcher.Matches("/bla*bla/test", "/blaXXXbl/test"))
	assert.False(t, matcher.Matches("/*bla/test", "XXXblab/test"))
	assert.False(t, matcher.Matches("/*bla/test", "XXXbl/test"))

	assert.False(t, matcher.Matches("/????", "/bala/bla"))
	assert.False(t, matcher.Matches("/**/*bla", "/bla/bla/bla/bbb"))

	assert.True(t, matcher.Matches("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing/"))
	assert.True(t, matcher.Matches("/*bla*/**/bla/*", "/XXXblaXXXX/testing/testing/bla/testing"))
	assert.True(t, matcher.Matches("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing"))
	assert.True(t, matcher.Matches("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing.jpg"))

	assert.True(t, matcher.Matches("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing/"))
	assert.True(t, matcher.Matches("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing"))
	assert.True(t, matcher.Matches("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing"))
	assert.False(t, matcher.Matches("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing/testing"))

	assert.False(t, matcher.Matches("/x/x/**/bla", "/x/x/x/"))

	assert.True(t, matcher.Matches("/foo/bar/**", "/foo/bar"))

	assert.True(t, matcher.Matches("", ""))
}

func TestSpaceInTokens(t *testing.T) {
	assert.True(t, matcher.Matches("/group/sales/members", "/group/sales/members"))
	assert.False(t, matcher.Matches("/group/sales/members", "/Group/  sales/Members"))
}
