_default:
  just -l

build:
  cargo build --release

run action infile outfile: build
  ./target/release/c {{action}} {{infile}} {{outfile}}
