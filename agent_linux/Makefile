all: clean
	@ echo "    * Building agent_linux plugin"
	@ mkdir -p dist
	@ cp config.yaml ax_config.axs ./dist/
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildvcs=false -buildmode=plugin -ldflags="-s -w" -o ./dist/agent_linux.so pl_main.go
	@ echo "      done..."
	@ echo "    * Building agent binaries (C++)"
	@ (cd src_cpp && $(MAKE) --no-print-directory SKIP_CONFIG=0 TARGET=agent_linux_amd64)
	@ cp -r src_cpp ./dist/src_cpp
	@ find ./dist/src_cpp -maxdepth 1 -type f -name "agent_linux*" -delete
	@ find ./dist/src_cpp -maxdepth 1 -type f -name "config.h" -delete
	@ rm -rf ./dist/src_cpp/build
	@ echo "      done..."

clean:
	@ rm -rf dist

.PHONY: all clean
