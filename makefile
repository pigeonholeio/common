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
	@echo "Generating API types..."
	@$(OAPI_CODEGEN) --package sdk -generate types -o types.gen.go $(OPENAPI_SPEC)
	
	@echo "Generating API server fiber stubs..."
	@mkdir -p ../server/src/stub
	@$(OAPI_CODEGEN) --package sdk -generate fiber -o ../server/src/stub/server.gen.go $(OPENAPI_SPEC)
	@$(OAPI_CODEGEN) --package sdk -generate types,spec -o ../server/src/stub/types.gen.go $(OPENAPI_SPEC)
	@$(OAPI_CODEGEN) --package sdk -generate client -o ../cli/src/sdk/client.gen.go $(OPENAPI_SPEC)
	@$(OAPI_CODEGEN) --package sdk -generate types -o ../cli/src/sdk/types.gen.go $(OPENAPI_SPEC)
	
# 	@sed -i '/"fmt"/a \    sdk "github.com/pigeonholeio/common"' ../server/src/stub/server.gen.go
	@go mod tidy
	@go mod vendor
	@echo "API code generation complete."
	$(MAKE) commit
commit: 
	git add .
	git commit -m'updated sdk'
	git push
patch:
	@if ! grep -q '	PostAuthOidcCleverHandler(ctx context.Context, provider \*OIDCProvider, idPToken \*OIDCProviderToken, reqEditors ...RequestEditorFn) (\*http.Response, error)' ../cli/src/sdk/client.gen.go; then \
		sed -i.bak '/PostAuthOidcHandlerGeneric(ctx context.Context, body PostAuthOidcHandlerGenericJSONRequestBody, reqEditors \.\.\.RequestEditorFn) (\*http.Response, error)/a\
    PostAuthOidcCleverHandler(ctx context.Context, provider *OIDCProvider, idPToken *OIDCProviderToken, reqEditors ...RequestEditorFn) (*http.Response, error)' ../cli/src/sdk/client.gen.go && rm -f ../cli/src/sdk/client.gen.go.bak; \
	else \
		echo "Line already exists, skipping insert"; \
	fi

# patch:
# 	sed -i '/	PostAuthOidcHandlerGeneric(ctx context.Context, body PostAuthOidcHandlerGenericJSONRequestBody, reqEditors \.\.\.RequestEditorFn) (\*http.Response, error)/a	\
# 							\tPostAuthOidcCleverHandler(ctx context.Context, provider *OIDCProvider, idPToken *OIDCProviderToken, reqEditors ...RequestEditorFn) (*http.Response, error)' ../cli/src/sdk/client.gen.go
