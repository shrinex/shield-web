package pattern

import "strings"

type (
	// Matcher is an interface for components that can
	// match source strings against a specified pattern string.
	Matcher interface {
		// Matches returns true if the given source matches the specified pattern, false otherwise.
		//
		// pattern – the pattern to match against
		// path – the source to match
		Matches(string, string) bool
	}

	// Matcher implementation for Ant-style path patterns. Examples are provided below.
	// Part of this mapping code has been kindly borrowed from Apache Ant .
	// The mapping matches URLs using the following rules:
	// ? matches one character
	// * matches zero or more characters
	// ** matches zero or more 'directories' in a path
	//
	// Some examples:
	// com/t?st.jsp — matches com/test.jsp but also com/tast.jsp or com/txst.jsp
	// com/*.jsp — matches all .jsp files in the com directory
	// com/**/test.jsp — matches all test.jsp files underneath the com path
	// org/springframework/**/*.jsp — matches all .jsp files underneath the org/springframework path
	// org/**/servlet/bla.jsp — matches org/springframework/servlet/bla.jsp but also org/springframework/testing/servlet/bla.jsp and org/servlet/bla.jsp
	// NOTE: This class was borrowed from Spring Framework
	antPathMatcher struct {
	}
)

const pathSeparator = "/"

var _ Matcher = (*antPathMatcher)(nil)

func NewMatcher() Matcher {
	return &antPathMatcher{}
}

func (m *antPathMatcher) Matches(pattern string, path string) bool { // nolint
	if strings.HasPrefix(pattern, pathSeparator) != strings.HasPrefix(path, pathSeparator) {
		return false
	}

	patternDirs := tokenize(pattern, pathSeparator)
	pathDirs := tokenize(path, pathSeparator)

	patternIdxStart := 0
	patternIdxEnd := len(patternDirs) - 1
	pathIdxStart := 0
	pathIdxEnd := len(pathDirs) - 1

	// Match all elements up to the first **
	for patternIdxStart <= patternIdxEnd && pathIdxStart <= pathIdxEnd {
		patDir := patternDirs[patternIdxStart]
		if patDir == "**" {
			break
		}
		if !m.matchStrings(patDir, pathDirs[pathIdxStart]) {
			return false
		}
		patternIdxStart++
		pathIdxStart++
	}

	if pathIdxStart > pathIdxEnd {
		// Path is exhausted, only match if rest of pattern is * or **'s
		if patternIdxStart > patternIdxEnd {
			if strings.HasSuffix(pattern, pathSeparator) {
				return strings.HasSuffix(path, pathSeparator)
			}
			return !strings.HasSuffix(path, pathSeparator)
		}

		if patternIdxStart == patternIdxEnd &&
			patternDirs[patternIdxStart] == ("*") &&
			strings.HasSuffix(path, pathSeparator) {
			return true
		}
		for i := patternIdxStart; i <= patternIdxEnd; i++ {
			if patternDirs[i] != ("**") {
				return false
			}
		}
		return true
	} else if patternIdxStart > patternIdxEnd {
		// String not exhausted, but pattern is. Failure.
		return false
	}

	// up to last '**'
	for patternIdxStart <= patternIdxEnd && pathIdxStart <= pathIdxEnd {
		patDir := patternDirs[patternIdxEnd]
		if patDir == ("**") {
			break
		}
		if !m.matchStrings(patDir, pathDirs[pathIdxEnd]) {
			return false
		}
		patternIdxEnd--
		pathIdxEnd--
	}
	if pathIdxStart > pathIdxEnd {
		// String is exhausted
		for i := patternIdxStart; i <= patternIdxEnd; i++ {
			if patternDirs[i] != ("**") {
				return false
			}
		}
		return true
	}

	for patternIdxStart != patternIdxEnd && pathIdxStart <= pathIdxEnd {
		patIdxTmp := -1
		for i := patternIdxStart + 1; i <= patternIdxEnd; i++ {
			if patternDirs[i] == ("**") {
				patIdxTmp = i
				break
			}
		}
		if patIdxTmp == patternIdxStart+1 {
			// '**/**' situation, so skip one
			patternIdxStart++
			continue
		}
		// Find the pattern between padIdxStart & padIdxTmp in str between
		// strIdxStart & strIdxEnd
		patLength := patIdxTmp - patternIdxStart - 1
		strLength := pathIdxEnd - pathIdxStart + 1
		foundIdx := -1

	strLoop:
		for i := 0; i <= strLength-patLength; i++ {
			for j := 0; j < patLength; j++ {
				subPat := patternDirs[patternIdxStart+j+1]
				subStr := pathDirs[pathIdxStart+i+j]
				if !m.matchStrings(subPat, subStr) {
					continue strLoop
				}
			}
			foundIdx = pathIdxStart + i
			break
		}

		if foundIdx == -1 {
			return false
		}

		patternIdxStart = patIdxTmp
		pathIdxStart = foundIdx + patLength
	}

	for i := patternIdxStart; i <= patternIdxEnd; i++ {
		if patternDirs[i] != ("**") {
			return false
		}
	}

	return true
}

func (m *antPathMatcher) matchStrings(pattern string, str string) bool { // nolint
	patArr := []byte(pattern)
	strArr := []byte(str)
	patIdxStart := 0
	patIdxEnd := len(patArr) - 1
	strIdxStart := 0
	strIdxEnd := len(strArr) - 1
	var ch byte

	containsStar := false
	for _, aPatArr := range patArr {
		if aPatArr == '*' {
			containsStar = true
			break
		}
	}

	if !containsStar {
		// No '*'s, so we make a shortcut
		if patIdxEnd != strIdxEnd {
			return false // Pattern and string do not have the same size
		}

		for i := 0; i <= patIdxEnd; i++ {
			ch = patArr[i]
			if ch != '?' {
				if ch != strArr[i] {
					return false // Character mismatch
				}
			}
		}
		return true // String matches against pattern
	}

	if patIdxEnd == 0 {
		return true // Pattern contains only '*', which matches anything
	}

	// Process characters before first star
	ch = patArr[patIdxStart]
	for ch != '*' && strIdxStart <= strIdxEnd {
		if ch != '?' {
			if ch != strArr[strIdxStart] {
				return false // Character mismatch
			}
		}
		patIdxStart++
		strIdxStart++
		ch = patArr[patIdxStart]
	}
	if strIdxStart > strIdxEnd {
		// All characters in the string are used. Check if only '*'s are
		// left in the pattern. If so, we succeeded. Otherwise, failure.
		for i := patIdxStart; i <= patIdxEnd; i++ {
			if patArr[i] != '*' {
				return false
			}
		}
		return true
	}

	// Process characters after last star
	ch = patArr[patIdxEnd]
	for ch != '*' && strIdxStart <= strIdxEnd {
		if ch != '?' {
			if ch != strArr[strIdxEnd] {
				return false // Character mismatch
			}
		}
		patIdxEnd--
		strIdxEnd--
		ch = patArr[patIdxEnd]
	}
	if strIdxStart > strIdxEnd {
		// All characters in the string are used. Check if only '*'s are
		// left in the pattern. If so, we succeeded. Otherwise, failure.
		for i := patIdxStart; i <= patIdxEnd; i++ {
			if patArr[i] != '*' {
				return false
			}
		}
		return true
	}

	// process pattern between stars. padIdxStart and patIdxEnd point
	// always to a '*'.
	for patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd {
		patIdxTmp := -1
		for i := patIdxStart + 1; i <= patIdxEnd; i++ {
			if patArr[i] == '*' {
				patIdxTmp = i
				break
			}
		}
		if patIdxTmp == patIdxStart+1 {
			// Two stars next to each other, skip the first one.
			patIdxStart++
			continue
		}
		// Find the pattern between padIdxStart & padIdxTmp in str between
		// strIdxStart & strIdxEnd
		patLength := patIdxTmp - patIdxStart - 1
		strLength := strIdxEnd - strIdxStart + 1
		foundIdx := -1
	strLoop:
		for i := 0; i <= strLength-patLength; i++ {
			for j := 0; j < patLength; j++ {
				ch = patArr[patIdxStart+j+1]
				if ch != '?' {
					if ch != strArr[strIdxStart+i+j] {
						continue strLoop
					}
				}
			}

			foundIdx = strIdxStart + i
			break
		}

		if foundIdx == -1 {
			return false
		}

		patIdxStart = patIdxTmp
		strIdxStart = foundIdx + patLength
	}

	// All characters in the string are used. Check if only '*'s are left
	// in the pattern. If so, we succeeded. Otherwise, failure.
	for i := patIdxStart; i <= patIdxEnd; i++ {
		if patArr[i] != '*' {
			return false
		}
	}

	return true
}

func tokenize(path, sep string) []string {
	ss := make([]string, 0)
	for _, s := range strings.Split(path, sep) {
		if len(s) == 0 {
			continue
		}
		ss = append(ss, s)
	}
	return ss
}
