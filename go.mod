module github.com/shrinex/shield-web

go 1.18

// go mod edit -replace='github.com/shrinex/shield@v0.0.0-unpublished'='../shield'
// go get github.com/shrinex/shield@v0.0.0-unpublished

//replace github.com/shrinex/shield v0.0.0-unpublished => ../shield

//github.com/shrinex/shield v0.0.0-unpublished
require github.com/stretchr/testify v1.8.2

require github.com/shrinex/shield v0.0.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
