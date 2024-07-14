@echo off

rmdir /S /Q wireshark\plugins\epan\tracee-event
rmdir /S /Q wireshark\plugins\epan\tracee-network-capture
rmdir /S /Q wireshark\plugins\wiretap\tracee-json
del /Q wireshark\plugins\epan\common.h
del /Q wireshark\plugins\epan\wsjson_extensions.c
del /Q wireshark\CMakeListsCustom.txt
rmdir /S /Q build