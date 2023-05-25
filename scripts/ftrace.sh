#!/usr/bin/env bash
TRACE_DIR=/sys/kernel/debug/tracing

# clear
sudo echo 0 > $TRACE_DIR/tracing_on
sudo echo > $TRACE_DIR/set_graph_function
sudo echo > $TRACE_DIR/set_ftrace_filter
sudo echo nop > $TRACE_DIR/current_tracer

# setting
sudo echo function_graph > $TRACE_DIR/current_tracer
sudo echo 5 > $TRACE_DIR/max_graph_depth
sudo echo http_server_worker_CMWQ > $TRACE_DIR/set_graph_function

# execute
sudo echo 1 > $TRACE_DIR/tracing_on
./htstress localhost:8081 -n 1
sudo echo 0 > $TRACE_DIR/tracing_on