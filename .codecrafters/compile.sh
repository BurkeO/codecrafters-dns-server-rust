#!/bin/sh
#
# This script is used to compile your program on CodeCrafters
#
# This runs before .codecrafters/run.sh
#
# Learn more: https://codecrafters.io/program-interface

set -e # Exit on failure
export RUST_BACKTRACE=1
cargo build --release --target-dir=/tmp/codecrafters-build-dns-server-rust --manifest-path Cargo.toml
