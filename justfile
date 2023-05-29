# deterministically tar a directory
tar dir outfile:
  tar cvf - {{dir}} | gzip -n > {{outfile}}.tar.gz

# untars a tar
untar file:
  tar xvf {{file}}

# run this crate
run action infile outfile:
  cargo lrun --release -- {{action}} {{infile}} {{outfile}}
