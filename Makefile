export NAME = dnstap
export REPO = $(NAME)
export GOPATH := $(shell cd `pwd -P`/../../../..; pwd -P)
export GOROOT := $(shell cd $(GOPATH)/go; pwd -P)
export PATH := $(GOROOT)/bin:$(PATH)

export DEB_BINS=$(NAME)

include $(GOPATH)/Makefile.project

bin/%: build_data
	go install $(NAME)
