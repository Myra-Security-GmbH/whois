GO      = go
GOLINT  = $(GOPATH)/bin/gometalinter
TLD_URL = https://publicsuffix.org/list/public_suffix_list.dat

all: \
	vendor \
	tldlist.go

vendor:
	glide install

test:
	$(GO) test -race $$($(GO) list ./... | grep -v "/vendor/")

$(GOPATH)/bin/goconst:
	$(GO) get github.com/jgautheron/goconst/cmd/goconst

$(GOPATH)/bin/ineffassign:
	$(GO) get github.com/gordonklaus/ineffassign

$(GOLINT):
	$(GO) get -u github.com/alecthomas/gometalinter

lint: \
	$(GOLINT) \
	$(GOPATH)/bin/goconst \
	$(GOPATH)/bin/ineffassign \
	$(GOPATH)/bin/varcheck \
	$(GOPATH)/bin/structcheck \
	$(GOPATH)/bin/aligncheck \
	$(GOPATH)/bin/gocyclo \
	$(GOPATH)/bin/interfacer \
	$(GOPATH)/bin/gosimple \
	$(GOPATH)/bin/deadcode \
	$(GOPATH)/bin/unconvert \
	$(GOPATH)/bin/staticcheck \
	$(GOPATH)/bin/gas
		$(GOLINT) --deadline 30s 

$(GOPATH)/bin/aligncheck:
	$(GO) get github.com/opennota/check/cmd/aligncheck

$(GOPATH)/bin/structcheck:
	$(GO) get github.com/opennota/check/cmd/structcheck

$(GOPATH)/bin/varcheck:
	$(GO) get github.com/opennota/check/cmd/varcheck

$(GOPATH)/bin/gocyclo:
	$(GO) get github.com/fzipp/gocyclo

$(GOPATH)/bin/interfacer:
	$(GO) get mvdan.cc/interfacer

$(GOPATH)/bin/gosimple:
	$(GO) get honnef.co/go/tools/cmd/gosimple

$(GOPATH)/bin/deadcode:
	$(GO) get github.com/tsenart/deadcode

$(GOPATH)/bin/unconvert:
	$(GO) get github.com/mdempsky/unconvert

$(GOPATH)/bin/staticcheck:
	$(GO) get honnef.co/go/tools/cmd/staticcheck

$(GOPATH)/bin/gas:
	$(GO) get github.com/GoASTScanner/gas

tldlist.go:
	@echo "package whois" > $@
	@echo "var tldlist map[string]bool" >> $@
	@echo "func init() {" >> $@
	@echo "tldlist = make(map[string]bool)" >> $@
	@wget -q $(TLD_URL) -O - | grep -vE "^(|//.*)$$" | grep -v "^*" | sort | awk '{\
		print "tldlist[\""$$1"\"] = true"\
	}' >> $@
	@echo "}" >> $@
	@$(GO) fmt $@


.PHONY:all test lint vendor tldlist.go

