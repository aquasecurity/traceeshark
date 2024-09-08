#!/bin/sh

handler()
{
    kill -s INT $PID
}

/tracee/entrypoint.sh $@ &
PID=$!

trap handler INT TERM
wait $PID

chmod -R g+w /output