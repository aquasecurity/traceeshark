#!/bin/bash

# This code is taken from Wireshark! (wireshark/packaging/macosx/osx-app.sh.in)
# Original authors:
#		 Kees Cook <kees@outflux.net>
#		 Michael Wybrow <mjwybrow@users.sourceforge.net>
#		 Jean-Olivier Irisson <jo.irisson@gmail.com>
#
# Copyright (C) 2005 Kees Cook
# Copyright (C) 2005-2007 Michael Wybrow
# Copyright (C) 2007 Jean-Olivier Irisson

install_exclude_prefixes="/System/|/Library/|/usr/lib/|/usr/X11/|/opt/X11/|@executable_path"

rpathify_file () {
    local rpathify_exclude_prefixes="$install_exclude_prefixes|@rpath"

    # Fix a given executable, library, or plugin to be relocatable
    if [ ! -f "$1" ]; then
        return 0;
    fi

    #
    # OK, what type of file is this?
    #
    if ! filetype=$( otool -hv "$1" | grep -E MH_MAGIC | awk '{print $5}' ; exit "${PIPESTATUS[0]}" ) ; then
        echo "Unable to rpathify $1 in $( pwd ): file type failed."
        exit 1
    fi

    case "$filetype" in

    EXECUTE|DYLIB|BUNDLE)
        #
        # Executable, library, or plugin.  (Plugins
        # can be either DYLIB or BUNDLE; shared
        # libraries are DYLIB.)
        #
        # For DYLIB and BUNDLE, fix the shared
        # library identification.
        #
        if [[ "$filetype" = "DYLIB" || "$filetype" = "BUNDLE" ]]; then
            echo "Changing shared library identification of $1"
            base=$( echo "$1" | awk -F/ '{print $NF}' )
            #
            # The library will end up in a directory in
            # the rpath; this is what we should change its
            # ID to.
            #
            to=@rpath/$base
            /usr/bin/install_name_tool -id "$to" "$1"

            #
            # If we're a library and we depend on something in
            # @executable_path/../Frameworks, replace that with
            # @rpath.
            #
            otool_output=$(otool -L "$1" | grep @executable_path/../Frameworks | awk '{print $1}')
            while read -r dep_lib ; do
                base=$( echo "$dep_lib" | awk -F/ '{print $NF}' )
                to="@rpath/$base"
                echo "Changing reference to $dep_lib to $to in $1"
                /usr/bin/install_name_tool -change "$dep_lib" "$to" "$1"
            done <<< "$otool_output"

            #
            # Try to work around brotli's lack of a full path
            # https://github.com/google/brotli/issues/934
            #
            otool_output=$(otool -L "$1" | grep '^	libbrotli' | awk '{print $1}')
            while read -r base ; do
                to="@rpath/$base"
                echo "Changing reference to $base to $to in $1"
                /usr/bin/install_name_tool -change "$base" "$to" "$1"
            done <<< "$otool_output"
        fi

        #
        # Find our local rpaths and remove them.
        #
        otool -l "$1" | grep -A2 LC_RPATH \
            | awk '$1=="path" && $2 !~ /^@/ {print $2}' \
            | grep -E -v "$rpathify_exclude_prefixes" | \
        while read -r lc_rpath ; do
            echo "Stripping LC_RPATH $lc_rpath from $1"
            install_name_tool -delete_rpath "$lc_rpath" "$1"
        done

        #
        # Add -Wl,-rpath,@executable_path/../Frameworks
        # to the rpath, so it'll find the bundled
        # frameworks and libraries if they're referred
        # to by @rpath/, rather than having a wrapper
        # script tweak DYLD_LIBRARY_PATH.
        #
        if [[ "$filetype" = "EXECUTE" ]]; then
            if [ -d ../Frameworks ] ; then
                framework_path=../Frameworks
            elif [ -d ../../Frameworks ] ; then
                framework_path=../../Frameworks
            else
                echo "Unable to find relative path to Frameworks for $1 from $( pwd )"
                exit 1
            fi

            echo "Adding @executable_path/$framework_path to rpath of $1"
            /usr/bin/install_name_tool -add_rpath @executable_path/$framework_path "$1"
        fi

        #
        # Show the minimum supported version of macOS
        # for each executable or library
        #
        if [[ "$filetype" = "EXECUTE" || "$filetype" = "DYLIB" ]] ; then
            echo "Minimum macOS version for $1:"
            otool -l "$1" | grep -A3 LC_VERSION_MIN_MACOSX
        fi

        #
        # Get the list of dynamic libraries on which this
        # file depends, and select only the libraries that
        # are in $LIBPREFIX, as those are the only ones
        # that we'll be shipping in the app bundle; the
        # other libraries are system-supplied or supplied
        # as part of X11, will be expected to be on the
        # system on which the bundle will be installed,
        # and should be referred to by their full pathnames.
        #
        otool_output=$(otool -L "$1" \
            | grep -F compatibility \
            | cut -d\( -f1 \
            | grep -E -v "$rpathify_exclude_prefixes" \
            | sort \
            | uniq \
        )
        local libs=()
        while read -r lib ; do
            libs+=("$lib")
        done <<< "$otool_output"

        for lib in "${libs[@]}"; do
            #
            # Get the file name of the library.
            #
            base=$( echo "$lib" | awk -F/ '{print $NF}' )
            #
            # The library will end up in a directory in
            # the rpath; this is what we should change its
            # file name to.
            #
            to=@rpath/$base
            #
            # Change the reference to that library.
            #
            echo "Changing reference to $lib to $to in $1"
            /usr/bin/install_name_tool -change "$lib" "$to" "$1"
        done
        ;;
    esac
}

rpathify_file "$1"