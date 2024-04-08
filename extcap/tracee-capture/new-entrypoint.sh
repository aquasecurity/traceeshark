#!/bin/sh

handler()
{
    kill -s SIGINT $PID
}

/tracee/entrypoint.sh $@ &
PID=$!

trap handler SIGINT SIGTERM
wait $PID

chmod -R g+w /output