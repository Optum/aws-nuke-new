docs-build:
	docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material build

docs-serve:
	docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material

docs-seed:
	cp README.md docs/index.md

build:
	go build -ldflags '-s -w -extldflags="-static"' -o bin/aws-nuke main.go

generate:
	go generate ./...

test:
	go test ./...

test-integration:
	go test ./... -tags=integration
