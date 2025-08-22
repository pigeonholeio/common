# Makefile for Pigeonhole (server + CLI + API generation)

# Paths
API_DIR := .
OPENAPI_SPEC := openapi-spec.yaml

# Tools
OAPI_CODEGEN := oapi-codegen
GO := go

.PHONY: all api server cli clean

# Default target: regenerate API + build server + build CLI
all: api server cli

# Regenerate API code into separate packages
generate:
	@mkdir -p $(API_DIR)/common
	@echo "Generating API types..."
	@$(OAPI_CODEGEN) --package sdk -generate types -o types.gen.go $(OPENAPI_SPEC)
	
	@echo "Generating API server fiber stubs..."
	@mkdir -p ../server/src/stub
	@$(OAPI_CODEGEN) --package stub -generate fiber -o ../server/src/stub/server.gen.go $(OPENAPI_SPEC)
	@sed -i '/"fmt"/a \    sdk "github.com/pigeonholeio/common"' ../server/src/stub/server.gen.go
	@echo "API code generation complete."
