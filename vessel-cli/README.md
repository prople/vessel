# vessel-cli

`Vessel CLI` is a CLI application used as a client to communicate with the `Vessel RPC` server.
User can manage their `identity`, `agent` through this simple client application.

## Example

```shell
$ > prople-vesel-cli -h

Usage: prople-vessel-cli [OPTIONS] <COMMAND>

Commands:
  identity  
  agent     
  ping      
  help      Print this message or the help of the given subcommand(s)

Options:
      --enable-debug   
      --agent <AGENT>  
  -h, --help           Print help
  -V, --version        Print version
```

## Installation

```toml
[dependencies]
prople-vessel-cli = {version = "0.3.1"}
```