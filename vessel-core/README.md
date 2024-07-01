# vessel-core

This crate provides base abstractions of business logic for the `prople/vessel/vessel-core`. There are multiple important domains covered, which are:

- `identity`
- `connection` (soon)
- `social` (soon)
- `finance` (soon)

All of those domains will be managed in the `DDD (Domain Driven Design)` ways, and the code base will be structured through the `Modular Monolith Architecture`, which means, each of available domains will be able managed independently, and even will be able to deployed separately later.

Each of domains will have it's own `<domain>API` that will be used as an entrypoint to communicate between domains 

The main purpose of this package is to provide a domain abstraction for the `prople/vessel` needs. By providing an abstraction, it will help third party services or software engineers to create their own implementation, it's almost like a SDK in common. 

## Installation

```toml
[dependencies]
prople-vessel-core = {version = "0.1.0"}
```