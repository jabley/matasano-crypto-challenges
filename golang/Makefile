.PHONY: fmt test coverage

all: fmt test

fmt:
	goimports -w .

test:
	go test -coverprofile crypto.coverprofile
	# rewrite the generated .coverprofile files so that you can run the command
	# go tool cover -html=.matasano.coverprofile
	find . -name '*.coverprofile' -type f -exec sed -i '' 's|_'$(CURDIR)'|\.|' {} \;

coverage:
	go tool cover -html=./crypto.coverprofile
