include .env
export

OS_NAME := $(shell uname -s)

TRACEESHARK_CMAKE_OPTIONS := $(TRACEESHARK_CMAKE_OPTIONS) -DCMAKE_C_FLAGS="-Wno-documentation"

# update Wireshark source tree and build
all: sync build

clean:
	@rm -rf wireshark/build
	@rm -f wireshark/CMakeListsCustom.txt
	@rm -rf wireshark/plugins/epan/tracee-event
	@rm -rf wireshark/plugins/epan/tracee-network-capture
	@rm -f wireshark/plugins/epan/common.h
	@rm -f wireshark/plugins/epan/wsjson_extensions.c
	@rm -rf wireshark/plugins/wiretap/tracee-json

# sync plugin source files into Wireshark source
sync:
	@rsync -a CMakeListsCustom.txt wireshark/
	@rsync -a plugins/ wireshark/plugins/

build: sync
	@if ! [ -d "wireshark/build" ]; then \
		echo "Build directory doesn't exist, run \"make cmake\" first"; \
		exit 1; \
	fi

	@ninja -C wireshark/build

# update private configuration profile
install:
	@mkdir -p ~/.config/wireshark
	@cp -r profiles ~/.config/wireshark
	
	@mkdir -p ~/.local/lib/wireshark/extcap
	@cp extcap/tracee-capture.py ~/.local/lib/wireshark/extcap
	@if [ "$(OS_NAME)" = "Darwin" ]; then \
		sed -i '' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.local/lib/wireshark/extcap/tracee-capture.py; \
		cp extcap/tracee-capture.sh ~/.local/lib/wireshark/extcap; \
		chmod +x ~/.local/lib/wireshark/extcap/tracee-capture.sh; \
	else \
		sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.local/lib/wireshark/extcap/tracee-capture.py; \
		chmod +x ~/.local/lib/wireshark/extcap/tracee-capture.py; \
	fi
	@cp -r extcap/tracee-capture ~/.local/lib/wireshark/extcap
	@chmod +x ~/.local/lib/wireshark/extcap/tracee-capture/new-entrypoint.sh

	@mkdir -p ~/.config/wireshark/extcap
	@cp extcap/tracee-capture.py ~/.config/wireshark/extcap
	@if [ "$(OS_NAME)" = "Darwin" ]; then \
		sed -i '' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.config/wireshark/extcap/tracee-capture.py; \
		cp extcap/tracee-capture.sh ~/.config/wireshark/extcap; \
		chmod +x ~/.config/wireshark/extcap/tracee-capture.sh; \
	else \
		sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.config/wireshark/extcap/tracee-capture.py; \
		chmod +x ~/.config/wireshark/extcap/tracee-capture.py; \
	fi
	@cp -r extcap/tracee-capture ~/.config/wireshark/extcap
	@chmod +x ~/.config/wireshark/extcap/tracee-capture/new-entrypoint.sh

	$(eval WS_VERSION_SHORT := $(shell if [ -x "wireshark/build/run/wireshark" ]; then wireshark/build/run/wireshark --version | grep -o -E "Wireshark [0-9]+\.[0-9]+\.[0-9]+" | grep -o -E "[0-9]+\.[0-9]+"; fi))
ifeq ($(OS_NAME),Darwin)
	$(eval WS_VERSION_DIR := $(subst .,-,$(WS_VERSION_SHORT)))
else
	$(eval WS_VERSION_DIR := $(WS_VERSION_SHORT))
endif

	@mkdir -p ~/.local/lib/wireshark/plugins/$(WS_VERSION_DIR)/epan
	@mkdir -p ~/.local/lib/wireshark/plugins/$(WS_VERSION_DIR)/wiretap
	
	@cp wireshark/build/run/tracee-event* ~/.local/lib/wireshark/plugins/$(WS_VERSION_DIR)/epan/tracee-event.so
	@cp wireshark/build/run/tracee-network-capture* ~/.local/lib/wireshark/plugins/$(WS_VERSION_DIR)/epan/tracee-network-capture.so
	@cp wireshark/build/run/tracee-json* ~/.local/lib/wireshark/plugins/$(WS_VERSION_DIR)/wiretap/tracee-json.so

# build and run
run: all install
	@wireshark/build/run/wireshark

# build and run with debug logging
debug: all install
	@wireshark/build/run/wireshark --log-level DEBUG

# prepare build directory (needed before building for the first time)
cmake: clean sync
	@rm -rf wireshark/build && mkdir wireshark/build
# Wireshark changed DISABLE_WERROR to ENABLE_WERROR at some point. Use both for compatibility (even though it causes a cmake warning to be thrown)
ifeq ($(WERROR),y)
	@cmake -G Ninja -DTRACEESHARK_VERSION=$(TRACEESHARK_VERSION) -DENABLE_CCACHE=Yes -DENABLE_WERROR=ON -DDISABLE_WERROR=OFF $(TRACEESHARK_CMAKE_OPTIONS) -S wireshark -B wireshark/build
else
	@cmake -G Ninja -DTRACEESHARK_VERSION=$(TRACEESHARK_VERSION) -DENABLE_CCACHE=Yes -DENABLE_WERROR=OFF -DDISABLE_WERROR=ON $(TRACEESHARK_CMAKE_OPTIONS) -S wireshark -B wireshark/build
endif

dist: all
	@rm -rf dist/workdir
	@mkdir dist/workdir
	@cp dist/install.sh dist/workdir

	@cp wireshark/build/run/tracee-event* dist/workdir/tracee-event.so
	@cp wireshark/build/run/tracee-network-capture* dist/workdir/tracee-network-capture.so
	@cp wireshark/build/run/tracee-json* dist/workdir/tracee-json.so

	@if [ "$(OS_NAME)" = "Darwin" ]; then \
		scripts/macos_rpathify.sh dist/workdir/tracee-json.so; \
		scripts/macos_rpathify.sh dist/workdir/tracee-event.so; \
		scripts/macos_rpathify.sh dist/workdir/tracee-network-capture.so; \
	fi
	
	@cp -r profiles dist/workdir
	@cp -r extcap dist/workdir

	@rm dist/workdir/extcap/tracee-capture.bat
	@if [ "$(OS_NAME)" = "Linux" ]; then \
		rm dist/workdir/extcap/tracee-capture.sh; \
	fi

	@if [ "$(OS_NAME)" = "Linux" ]; then \
		sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' dist/workdir/extcap/tracee-capture.py; \
	else \
		sed -i '' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' dist/workdir/extcap/tracee-capture.py; \
	fi

	$(eval WS_VERSION := $(shell wireshark/build/run/wireshark --version | grep -o -E "Wireshark [0-9]+\.[0-9]+\.[0-9]+" | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+"))
	@echo $(WS_VERSION) > dist/workdir/ws_version.txt
	
	@cd dist/workdir && zip -r ../traceeshark-v$(TRACEESHARK_VERSION)-$(shell echo "${OS_NAME}" | tr '[A-Z]' '[a-z]')-$(shell uname -m)-wireshark-$(WS_VERSION).zip .
