.PHONY: fmt test coverage

all: fmt test

fmt:
	goimports -w .

test:
	go test -coverprofile crypto.coverprofile
	find . -name '*.coverprofile' -type f -exec sed -i '' 's|_'$(CURDIR)'|\.|' {} \;

coverage:
	go tool cover -html=./crypto.coverprofile
