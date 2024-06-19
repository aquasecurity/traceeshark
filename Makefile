include .env
export

OS_NAME := $(shell uname -s)

# update wireshark source tree and build
all: copy-source build

# copy only source files to wireshark source tree
copy-source:
	@if [ -d "wireshark/plugins/epan/tracee-event" ]; then \
        cp plugins/epan/common.h wireshark/plugins/epan; \
        cp plugins/epan/wsjson_extensions.c wireshark/plugins/epan; \
        cp plugins/epan/tracee-event/internal_defs.c wireshark/plugins/epan/tracee-event; \
        cp plugins/epan/tracee-event/packet-tracee.c wireshark/plugins/epan/tracee-event; \
        cp plugins/epan/tracee-event/postdissectors.c wireshark/plugins/epan/tracee-event; \
        cp plugins/epan/tracee-event/wanted_fields.c wireshark/plugins/epan/tracee-event; \
        cp plugins/epan/tracee-event/tracee.h wireshark/plugins/epan/tracee-event; \
        cp plugins/epan/tracee-network-capture/packet-tracee-network-capture.c wireshark/plugins/epan/tracee-network-capture; \
    else \
        error "Tracee plugin directory doesn't exist, run \"make cmake\" first"; \
    fi

	@if [ -d "wireshark/plugins/wiretap/tracee-json" ]; then \
        cp plugins/wiretap/tracee-json/tracee-json.c wireshark/plugins/wiretap/tracee-json; \
    else \
        error "Tracee plugin directory doesn't exist, run \"make cmake\" first"; \
    fi

# copy all project files to wireshark source tree
copy-all:
	@cp -r plugins wireshark/
	@cp CMakeListsCustom.txt wireshark/

build:
	@if [ -d "wireshark/build" ]; then \
        ninja -C wireshark/build; \
    else \
        error "Build directory doesn't exist, run \"make cmake\" first"; \
    fi

# update private configuration profile
install:
	$(eval WS_VERSION_SHORT := $(shell wireshark/build/run/wireshark --version | grep -o -E "Wireshark [0-9]+\.[0-9]+\.[0-9]+" | grep -o -E "[0-9]+\.[0-9]+"))
	@mkdir -p ~/.config/wireshark
	@cp -r profiles ~/.config/wireshark
	
	@mkdir -p ~/.local/lib/wireshark/extcap
	@cp extcap/tracee-capture.py ~/.local/lib/wireshark/extcap
	@sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.local/lib/wireshark/extcap/tracee-capture.py
	@if [ "$(OS_NAME)" == "Darwin" ]; then \
		cp extcap/tracee-capture.sh ~/.local/lib/wireshark/extcap; \
		chmod +x ~/.local/lib/wireshark/extcap/tracee-capture.sh; \
	else \
		chmod +x ~/.local/lib/wireshark/extcap/tracee-capture.py; \
	fi
	@cp -r extcap/tracee-capture ~/.local/lib/wireshark/extcap
	@chmod +x ~/.local/lib/wireshark/extcap/tracee-capture/new-entrypoint.sh

	@mkdir -p ~/.config/wireshark/extcap
	@cp extcap/tracee-capture.py ~/.config/wireshark/extcap
	@sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' ~/.config/wireshark/extcap/tracee-capture.py
	@if [ "$(OS_NAME)" == "Darwin" ]; then \
		cp extcap/tracee-capture.sh ~/.config/wireshark/extcap; \
		chmod +x ~/.config/wireshark/extcap/tracee-capture.sh; \
	else \
		chmod +x ~/.config/wireshark/extcap/tracee-capture.py; \
	fi
	@cp -r extcap/tracee-capture ~/.config/wireshark/extcap
	@chmod +x ~/.config/wireshark/extcap/tracee-capture/new-entrypoint.sh

	@mkdir -p ~/.local/lib/wireshark/plugins/epan
	@mkdir -p ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/epan

	@if [ -e "wireshark/build/run/tracee-event" ]; then \
		cp wireshark/build/run/tracee-event ~/.local/lib/wireshark/plugins/epan/tracee-event.so; \
		cp wireshark/build/run/tracee-event ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/epan/tracee-event.so; \
	else \
		cp wireshark/build/run/tracee-event.so* ~/.local/lib/wireshark/plugins/epan; \
		cp wireshark/build/run/tracee-event.so* ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/epan; \
	fi

	@if [ -e "wireshark/build/run/tracee-network-capture" ]; then \
		cp wireshark/build/run/tracee-network-capture ~/.local/lib/wireshark/plugins/epan/tracee-network-capture.so; \
		cp wireshark/build/run/tracee-network-capture ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/epan/tracee-network-capture.so; \
	else \
		cp wireshark/build/run/tracee-network-capture.so* ~/.local/lib/wireshark/plugins/epan; \
		cp wireshark/build/run/tracee-network-capture.so* ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/epan; \
	fi

	@mkdir -p ~/.local/lib/wireshark/plugins/wiretap
	@mkdir -p ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/wiretap

	@if [ -e "wireshark/build/run/tracee-json" ]; then \
		cp wireshark/build/run/tracee-json ~/.local/lib/wireshark/plugins/wiretap/tracee-json.so; \
		cp wireshark/build/run/tracee-json ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/wiretap/tracee-json.so; \
	else \
		cp wireshark/build/run/tracee-json.so* ~/.local/lib/wireshark/plugins/wiretap; \
		cp wireshark/build/run/tracee-json.so* ~/.local/lib/wireshark/plugins/$(WS_VERSION_SHORT)/wiretap; \
	fi

# build and run
run: all install
	@wireshark/build/run/wireshark

# build and run with debug logging
debug: all install
	@wireshark/build/run/wireshark --log-level DEBUG

# prepare build directory (needed before building for the first time)
cmake: copy-all
	@rm -rf wireshark/build && mkdir wireshark/build
ifneq ($(USE_QT5),y)
	@cmake -G Ninja -DTRACEESHARK_VERSION=$(TRACEESHARK_VERSION) -DENABLE_CCACHE=Yes -S wireshark -B wireshark/build
else
	@cmake -G Ninja -DTRACEESHARK_VERSION=$(TRACEESHARK_VERSION) -DENABLE_CCACHE=Yes -DUSE_qt6=OFF -S wireshark -B wireshark/build
endif

dist: all
	@rm -rf dist/workdir
	@mkdir dist/workdir
	@cp dist/install.sh dist/workdir

	@if [ -e "wireshark/build/run/tracee-event" ]; then \
		cp wireshark/build/run/tracee-event dist/workdir/tracee-event.so; \
	else \
		cp wireshark/build/run/tracee-event.so* dist/workdir; \
	fi

	@if [ -e "wireshark/build/run/tracee-network-capture" ]; then \
		cp wireshark/build/run/tracee-network-capture dist/workdir/tracee-network-capture.so; \
	else \
		cp wireshark/build/run/tracee-network-capture.so* dist/workdir; \
	fi
	
	@if [ -e "wireshark/build/run/tracee-json" ]; then \
		cp wireshark/build/run/tracee-json dist/workdir/tracee-json.so; \
	else \
		cp wireshark/build/run/tracee-json.so* dist/workdir; \
	fi

	@if [ "$(OS_NAME)" == "Darwin" ]; then \
		scripts/macos_rpathify.sh dist/workdir/tracee-json.so; \
		scripts/macos_rpathify.sh dist/workdir/tracee-event.so; \
		scripts/macos_rpathify.sh dist/workdir/tracee-network-capture.so; \
	fi
	
	@cp -r profiles dist/workdir
	@cp -r extcap dist/workdir

	@rm dist/workdir/extcap/tracee-capture.bat
	@if [ "$(OS_NAME)" == "Linux" ]; then \
		rm dist/workdir/extcap/tracee-capture.sh; \
	fi

	@sed -i'' -e 's/VERSION_PLACEHOLDER/$(TRACEESHARK_VERSION)/g' dist/workdir/extcap/tracee-capture.py

	$(eval WS_VERSION := $(shell wireshark/build/run/wireshark --version | grep -o -E "Wireshark [0-9]+\.[0-9]+\.[0-9]+" | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+"))
	@echo $(WS_VERSION) > dist/workdir/ws_version.txt
	
	@cd dist/workdir && zip -r ../traceeshark-v$(TRACEESHARK_VERSION)-$(shell echo "${OS_NAME}" | tr '[A-Z]' '[a-z]')-$(shell uname -m)-wireshark-$(WS_VERSION).zip .
