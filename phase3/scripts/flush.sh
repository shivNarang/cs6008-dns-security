#!/bin/sh
docker exec resolver rndc flush && echo "resolver cache flushed"
