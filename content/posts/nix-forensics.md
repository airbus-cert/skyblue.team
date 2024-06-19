---
title: "Using Nix to setup a reproducible forensics environment"
date: 2024-06-18
Summary: "dadazd"
---

At `$WORK`, we are big proponents of responding to incidents using live
telemetry from our EDR, and instrumenting its huge power using its API. However,
it is not always possible to leverage this: we sometimes have to respond to
incidents where our usual tool suite is not available. In these cases, we
usually resort to good old disk and memory forensics, using a combination
of internal and publicly available tools such as [The Sleuth
Kit](https://www.sleuthkit.org/), [libyal](https://github.com/libyal), or
[Regrippy](https://github.com/airbus-cert/regrippy).

Historically, analysts were expected to figure out by themselves how to install
all the tools in our toolbox: this means battling with Python versions, relying
on package maintainers to keep packages up to date, and sometimes having to
maintain local builds of lesser-known applications. This led to a "works on my
machine" mentality which made it more difficult to switch computers or
temporarily deport our analysis environment to remote machines.

In parallel, several members of the team had been experimenting with
[Nix](https://nixos.org/), for various reasons: some to automate their
development environment, others as a way to access packages not available
in their distro's repositories. Nix, in a nutshell, is a [package
manager](https://nix.dev/manual/nix/2.22/introduction) whose build files
are written in a [functional language](https://nix.dev/tutorials/nix-language). The
[nixpkgs](https://github.com/NixOS/nixpkgs) GitHub repository contains
definitions for how to build an important number of open-source (as well
as some closed-source) software.

As a result, we worked on a solution using Nix to automatically setup all the
tools we were used to in an isolated environment (using
[nix-shell](https://nix.dev/manual/nix/2.22/command-ref/nix-shell)). This
meant having to write derivations (Nix packages) for most of our internal
tools, finding ways to handle private repositories, and making sure
various Python versions did not step over each other. This blog post will
attempt to show how we organized our environment, and how we overcame the
various issues faced during development.

## Basic organization

The environment is developped in its own Git repository, composed mostly
of Nix files. A `default.nix` file references most of our custom
derivations (stored in a `pkgs/` directory), and a `shell.nix` file uses
these derivations to build a shell containing all the tools we want.

```
$ tree .
├── pkgs
│   └── regrippy.nix
├── default.nix
└── shell.nix
```

```nix
# default.nix
{ pkgs ? (import (fetchTarball "https://github.com/nixos/nixpkgs/archive/56b667b4a7bc98bf219f6410bdffd1e60dab4bbf.tar.gz") {})}:
with pkgs;
{
    regrippy = callPackage ./pkgs/regrippy.nix {};
}
```

```nix
# shell.nix
let
  pkgs = import (fetchTarball "https://github.com/nixos/nixpkgs/archive/56b667b4a7bc98bf219f6410bdffd1e60dab4bbf.tar.gz") {};
  my = import ./default.nix { inherit pkgs; };
in
pkgs.mkShell {
  packages = with pkgs; [
    sleuthkit
  ] ++ [
    my.regrippy
  ];
}
```

This way, we can write our own package derivations while still enjoying
the derivations already written in `nixpkgs`. This environment can be
copied as-is to any machine with Nix installed and rebuilt with a simple
invocation of `nix-shell`.

## Exporting our forensics environment as a Docker image

Once we have a working nix-shell environment, we can use it for various
stuff other than just entering it with the `nix-shell` command. For
example, it becomes easy to build a Docker image containing your
environment already pre-configured: simply use the
[`dockerTools.buildNixShellImage`](https://ryantm.github.io/nixpkgs/builders/images/dockertools/#ssec-pkgs-dockerTools-buildNixShellImage)
function to automatically generate it.

```nix
# docker.nix
{ dockerTools
, nixShell
}:
dockerTools.buildNixShellImage {
    drv = nixShell;
}
```

```nix
# default.nix
{ pkgs ? ... }:
with pkgs;
{
    regrippy = ...;

    docker = pkgs.callPackage ./docker.nix { nixShell = import ./shell.nix {} };
}
```

```shell
$ nix-build . -A docker
$ docker load < result
```

## Using an environment with private packages on an external machine

As long as your custom derivations only fetch their sources from
publicly-available repositories, you're good to go: you can simply copy
your Nix files somewhere else and run `nix-shell`, and it will work.
However, if your derivations depend on code that's hosted on a private
forge, you might run into issues when trying to build them: your forensics
machine might not have access to the private repositories (for example,
when using an AWS EC2 to work on big, long-running analyses).

Thankfully, there's a program in the Nix toolbox which can solve this
issue:
[`nix-copy-closure`](https://github.com/NixOS/nix/blob/master/src/nix-copy-closure/nix-copy-closure.cc).
This program will copy the Nix store path you give it to a remote machine,
as well as every other store path it depends on. Copying is done through
SSH, and the remote user must be part of Nix's [trusted
users](https://nix.dev/manual/nix/2.22/command-ref/conf-file#conf-trusted-users),
because the command will send the store paths as unsigned [Nix
Archives](https://nix.dev/manual/nix/2.22/glossary#gloss-nar) (NARs),
which require special rights to import.

This means that you can copy over the entirety of your shell using these
two commands:

```shell
$ nix-build shell.nix
...
/nix/store/<nix-hash>-nix-shell
$ nix-copy-closure --to ubuntu@my-ec2.aws.com --use-substitutes --gzip /nix/store/<nix-hash>-nix-shell
```

The `--use-substitutes` argument will make sure that all derivations which
can be fetched from `cache.nixos.org` are fetched from there and not
copied through the SSH link (because their bandwidth is probably better
than yours).

We're also compressing the archives with GZip: NARs are basically a
concatenation of all files in a Nix store path (see Figure 5.2 in [the Nix
paper](https://edolstra.github.io/pubs/phd-thesis.pdf)), so they can get
pretty huge, but also benefit strongly from compression.

Finally, we need a way to setup the environment in the remote machine
(i.e. "enter" the shell). In order to do that, we can run the `export`
command in a nix-shell instance on the host, note down the contents of the
`PATH` variable (and other useful environment variables) and apply them on
the remote machine. Because the Nix store paths are the same, you end up
in the same environment as if you ran `nix-shell` on the remote machine.

We're using the following script:

```bash
cat <<EOF | ssh $to -- "cat > $REMOTE_SCRIPT_PATH"
#!/usr/bin/env bash

p="\$PATH"
$(nix-shell --pure --run 'export' | grep -F -e 'declare -x PATH=' -e 'declare -x PYTHONPATH=' -e 'declare -x PERL5LIB=')

export PATH="\$p:\$PATH"
export PS1="\[\033[00;32m\][\u@nix-shell:\w]\\\$ \[\033[00m\]"

bash --noprofile --norc -i
EOF
```

This will create a file on the remote machine which spawns a new Bash
instance with the same path environment variables as on your host. We're
using `nix-shell --pure` to only keep environment variables that are
actually set by nix-shell (by default, nix-shell merges your env with the
nix-shell's), and writing them as-is in the remote script. We're also
making sure we only *append* the nix-shell paths to the existing
variables, this way the remote user can keep using their tools while in
the environment.
