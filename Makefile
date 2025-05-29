fmt:
	find . -name '*.go' -not -path './vendor/*' -exec gofumpt -extra -s -w {} \;

prompt: fmt
	code2prompt --output prompt.md .