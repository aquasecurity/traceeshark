# update wireshark source tree and build
all: copy-source build

# copy only source files to wireshark source tree
copy-source:
	@if [ -d "wireshark/plugins/epan/tracee" ]; then \
        cp plugins/epan/tracee/packet-tracee-json.c wireshark/plugins/epan/tracee; \
    else \
        error "Tracee plugin directory doesn't exist, run \"make cmake\" first."; \
    fi

	@if [ -d "wireshark/plugins/wiretap/tracee" ]; then \
        cp plugins/wiretap/tracee/tracee-json.c wireshark/plugins/wiretap/tracee; \
    else \
        error "Tracee plugin directory doesn't exist, run \"make cmake\" first."; \
    fi

# copy all project files to wireshark source tree
copy-all:
	@cp -r plugins wireshark/
	@cp CMakeListsCustom.txt wireshark/

build:
	@if [ -d "wireshark/build" ]; then \
        ninja -C wireshark/build; \
    else \
        echo "Build directory doesn't exist, run \"make cmake\" first."; \
    fi

# update private configuration profile
install:
	@mkdir -p ~/.config/wireshark
	@cp -r profiles ~/.config/wireshark

# build and run
run: all install
	@wireshark/build/run/wireshark

# build and run with debug logging
debug: all install
	@wireshark/build/run/wireshark --log-level DEBUG

# prepare build directory (needed before building for the first time)
cmake: copy-all
	@rm -rf wireshark/build && mkdir wireshark/build
	@cmake -G Ninja -S wireshark -B wireshark/build