# Run inside `nix develop`. Every target covers each Go module in the repo
# (any directory holding a go.mod, outside .dev/ and .claude/).

MODULES := $(patsubst %/go.mod,%,$(shell find . -name go.mod -not -path './.dev/*' -not -path './.claude/*' 2>/dev/null))

define each_module
	@if [ -z "$(MODULES)" ]; then echo "no Go modules yet"; fi
	@set -e; for m in $(MODULES); do echo "== $$m"; (cd $$m && $(1)); done
endef

.PHONY: check fmt fmt-check vet staticcheck test test-short tidy pg-up pg-down pg-url

## check: everything CI runs (gofmt, vet, staticcheck, race tests)
check: fmt-check vet staticcheck test

fmt:
	$(call each_module,gofmt -w .)

fmt-check:
	$(call each_module,out=$$(gofmt -l .); test -z "$$out" || { echo "not gofmt-clean:"; echo "$$out"; exit 1; })

vet:
	$(call each_module,go vet ./...)

staticcheck:
	$(call each_module,staticcheck ./...)

test:
	$(call each_module,go test -race ./...)

test-short:
	$(call each_module,go test -short ./...)

tidy:
	$(call each_module,go mod tidy)

pg-up:
	@scripts/pg-scratch up

pg-down:
	@scripts/pg-scratch down

pg-url:
	@scripts/pg-scratch url
