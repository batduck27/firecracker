# Fuzzing

Fuzz tests generate a ton of random parameter arguments to the program and then validate that none cause it to crash.

## How do I run fuzz tests locally?

### Setup

To install `afl`, simply run

```shell
cargo update
cargo install --force afl --version=0.7.0
```

### Execution

To build the fuzz targets for AFL, run
```shell
# build all the targets
cargo afl build --features afl

# or specify the fuzz target to build
cargo afl build --features afl --bin block_fuzz_target
```

To run AFL on a fuzz target, do

```shell
export TARGET="target/debug/block_fuzz_target" # replace with the path of the target to be fuzzed
export INPUT_DIR="in" # replace with the path to the directory with starting input files
export OUTPUT_DIR="out" # replace with the path to the output directory where the fuzzer will record the crashes and will store the generated inputs
export TOTAL_TIME="--max_total_time=30" # replace with the desired fuzzer timeout (in seconds); leave it empty to run without fuzzer timeout (the fuzzer will run indefinitely)

cargo afl fuzz $TOTAL_TIME -i $INPUT_DIR -o $OUTPUT_DIR $TARGET
```

To see a list of available fuzzing targets, run:

```shell
ls ./src/
```

## AFL detected a crash, what do I do?

AFL will store the inputs which generated a crash in the `$OUTPUT_DIR/crashes`. To reproduce the error locally and get a backtrace, simply run:


```shell
export RUST_BACKTRACE=1
export TARGET="block_fuzz_target" # replace with the fuzz target name
export INPUT_FILE="$OUTPUT_DIR/crashes/__input_file__" # replace with the input file which generate a crash

cargo run --features stdin_fuzz $TARGET < $INPUT_FILE
```

This will reproduce the failing fuzz input and yield a usable stack trace.
