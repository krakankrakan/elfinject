# x64 ELF code injector

A simple ELF code injector for x64. Uses segment padding to infect a file and will run the code on binary startup. For educational purposes only!

## Getting Started

These instructions will set up all prerequisites to use the ELF injector.

### Prerequisites

The program relies on gcc and objdump. The following command installs these on Ubuntu:

```
sudo apt-get install gcc binutils
```

### Building

Simply cd into this directory and type:

```
make
```

## Usage

The following command takes a assembly file and outputs a the dumped code section as file:

```
./create_injectable_file.sh input output
```

The injector has to be used as follows:

```
Usage:
        -I/-i input_file  : the file used as input
        -O/-o output_file : the file to infect
        -C/-c input_file  : the raw binary with the code to inject
```

## Example
As an example, the injected_asm.S file can be used. Type:
```
./create_injectable_file.sh injected_asm.S inject
./elfinjector -i /bin/nc -o /home/user/bin/nc -c inject -P
./nc
```
This example will infect the /bin/nc file and print the letter "I" at startup of the binary. The output file can be found in /home/user/bin/nc.
