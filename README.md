Open-TEE project
=======

<a href="https://scan.coverity.com/projects/3441">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/3441/badge.svg"/>
</a>

This repository contains the overall configuration for the Open-TEE project and the associated documentation.

- [Overview](#overview)
- [Community](#community)
- [Setup](#setup-guide)
    - [Prerequisites](#prerequisites)
    - [Obtaining the Source](#obtaining-the-source)
    - [Building with CMake](#building-with-cmake)
    - [Configuration](#configuration)
    - [Running and Debugging](#running-and-debugging)
- [Options](#options)
    - [Command Line Option](#command-line-options)
    - [Environmental Variables](#environmental-variables)
- [FAQ](#faq)
- [Contact](#contact)
- [License](#license)

Overview
------

The goal of the Open-TEE open source project is to implement a "virtual TEE" compliant with the recent <a href="http://globalplatform.org/specificationsdevice.asp"> Global Platform TEE specifications </a>.

Our primary motivation for the virtual TEE is to use it as a tool for developers of Trusted Applications and researchers interested in using TEEs or building new protocols and systems on top of it. Although hardware-based TEEs are ubiquitous in smartphones and tablets ordinary developers and researchers do not have access to it. While the emerging Global Platform specifications may change this situation in the future, a fully functional virtual TEE can help developers and researchers right away.

We intend that Trusted Applications developed using our virtual TEE can be compiled and run for any target that complies with the specifications.

The Open-TEE project is being led by the <a href="https://ssg.aalto.fi">Secure Systems group</a> as part of our activities at the <a href="http://www.icri-sc.org/"> Intel Collaborative Research Institute for Secure Computing </a>

All activities of the project are public and all results are in the public domain. We welcome anyone interested to join us in contributing to the project.

Quickstart guide
------
A minimalistic guide is tested on Ubuntu 20.04 (Focal Fossa). If you run into any errors or need more information, see topics below or raise an issue.

NOTE: [We have also a docker envronment](#docker)!

**NEW**: For an enhanced development experience with automatic process management, see [Using devenv](#using-devenv) below.

### Traditional Build

      # prerequisite packages
      $ sudo apt-get install -y build-essential git pkg-config uuid-dev libelf-dev wget curl cmake ninja-build libfuse-dev libssl-dev

      # mbedtls 3.x.x: fetch, compile and install if not packaged for your distro
      # (Note: Tested with 3.6.5, but 3.x.y version should be sufficient)
      # (NOTE: If you already have installed mbedtls, update with your own risk and cautions!!)
      $ wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.x.y.tar.gz
      $ tar -xf v3.x.y.tar.gz && cd mbedtls-3.1.0
      $ cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
      $ make -j && sudo make install

      # Clone opentee
      $ git clone https://github.com/Open-TEE/Open-TEE.git
      $ cd Open-TEE

      # Build opentee with CMake
      # Note: Install location is "/opt/OpenTee"
      $ cmake -B build-cmake -G Ninja \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/opt/OpenTee
      $ cmake --build build-cmake
      $ sudo cmake --install build-cmake

      # Generate opentee conf
      $ sudo bash -c 'cat > /etc/opentee.conf << EOF
      [PATHS]
      ta_dir_path = /opt/OpenTee/lib/TAs
      core_lib_path = /opt/OpenTee/lib
      subprocess_manager = libManagerApi.so
      subprocess_launcher = libLauncherApi.so
      EOF'

      # Run opentee and connection test program
      $ /opt/OpenTee/bin/opentee-engine
      $ /opt/OpenTee/bin/conn_test_app

Using devenv
------

For a streamlined development workflow with automatic process management, use [devenv](https://devenv.sh/):

### Prerequisites

1. Install Nix:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
   ```

2. Install devenv:
   ```bash
   nix profile install nixpkgs#devenv
   ```

### Quick Start

      # Clone the repository
      $ git clone https://github.com/Open-TEE/Open-TEE.git
      $ cd Open-TEE

      # Enter devenv shell and build
      $ devenv shell
      $ opentee-build

      # Start the Open-TEE daemon with process supervision
      $ devenv up

      # In another terminal, run tests
      $ test-conn
      $ test-services

**Benefits of devenv:**
- ✅ Automatic process management (start/stop/restart)
- ✅ TUI for monitoring logs and processes
- ✅ No sudo required, no system-wide installation
- ✅ Auto-generated configuration
- ✅ Built-in test scripts (`test-conn`, `test-services`, etc.)
- ✅ Reproducible development environment

See [docs/DEVENV.md](docs/DEVENV.md) for complete documentation.

Docker
------
Docker environment tested on Ubuntu 20.04 (Focal Fossa) and Community docker engine 20.10.12. If you run on other platforms then you might need to adjust docker volumes. Please see tips for streamlining your development/usage

#### Basic usage

     # Prerequisite: Clone opentee source code
     # Please see quickstart guide points
     # 1. Google repo (skip if you already have it)
     # 2. Clone opentee

     # Run Docker
     $ cd docker
     $ ./build-docker.sh
     $ ./run-docker.sh

     # Inside docker: Compile and run opentee
     # Please see quickrstart guide points
     # 1. Build opentee and install
     # 2. Run opentee and connection test program

#### Docker environment tips

    a) OpenTEE prints its debug prints to syslog and therefore /dev/log
       is mounted. You can read logs from your host machine
    b) You can pass "--prefix="-option to autogen.sh and you can
       avoid sudo-location installation!
    c) Remember to change /etc/opentee.conf file paths if you are
       using "--prefix="-option
    d) Dockers "--ipc=host"-options allows to connect from outside to
       inside container. So you can run opentee deamon inside docker
       and your CA can connect it from outside docker container



Setup
------

This guide describes how to obtain and build Open-TEE from source on Ubuntu 20.04+ or other modern Linux distributions. Open-TEE uses CMake as its build system.

If you wish to build Open-TEE for Android, consult the Android specific build documentation at:

http://open-tee.github.io/android

### Prerequisites

You'll need to install `git`, `cmake`, `pkg-config` and the necessary build dependencies:

    $ sudo apt-get install git cmake ninja-build pkg-config build-essential uuid-dev libssl-dev libelf-dev libfuse-dev

Additionally, you need mbedTLS 3.x (the Ubuntu apt package may be older):

    $ wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.x.y.tar.gz
    $ tar -xf v3.x.y.tar.gz && cd mbedtls-3.x.y
    $ cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
    $ make -j && sudo make install
    $ sudo ldconfig

Introduce yourself to `git` if you haven't done so already:

    $ git config --global user.name "Firstname Lastname"
    $ git config --global user.email "name@example.com"

### Obtaining the Source

Clone the repository:

    $ git clone https://github.com/Open-TEE/Open-TEE.git
    $ cd Open-TEE


### Building with CMake

Configure and build using CMake:

    $ cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    $ cmake --build build

To install Open-TEE system-wide:

    $ sudo cmake --install build --prefix /opt/OpenTee

By default Open-TEE will be installed under `/opt/OpenTee`. The directory will contain the following subdirectories:

* `/opt/OpenTee/bin`       - executables

* `/opt/OpenTee/include`   - public header files

* `/opt/OpenTee/lib`       - shared library objects (_libdir_)

* `/opt/OpenTee/lib/TAs`   - trusted application objects (_tadir_)

#### CMake Build Options

The following CMake options are available:

* `-DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo` - Build type (default: Release)
* `-DBUILD_TESTS=ON|OFF` - Build test applications (default: ON)
* `-DBUILD_EXAMPLES=ON|OFF` - Build example applications (default: ON)
* `-DCMAKE_INSTALL_PREFIX=/path` - Installation prefix (default: /usr/local)

#### IDE Integration

CMake automatically generates `compile_commands.json` for IDE/LSP integration:

    $ cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
    $ ln -sf build/compile_commands.json .

This enables features like code completion, go-to-definition, and diagnostics in editors that support LSP (VS Code, Emacs, Vim, etc.).

### Configuration

Open the configuration file with your preferred editor:

    $ sudo $EDITOR /etc/opentee.conf

Add the sample configuration given below to the configuration file:

>
> [PATHS]
> ta\_dir\_path = _PATH_/_TO_/_TADIR_
> core\_lib\_path = _PATH_/_TO_/_LIBDIR_
> subprocess\_manager = libManagerApi.<span></span>so
> subprocess\_launcher = libLauncherApi.<span></span>so
>

where _PATHNAME_ is replaced with the absolute path to the parent directory of the Open-TEE directory you created earlier. The pathname must **not** include special variables such as `~` or `$HOME`.

For a standard CMake install you can use:

>
> [PATHS]
> ta\_dir\_path = /opt/OpenTee/lib/TAs
> core\_lib\_path = /opt/OpenTee/lib
> subprocess\_manager = libManagerApi.<span></span>so
> subprocess\_launcher = libLauncherApi.<span></span>so
>

### Running and Debugging

You are now ready to launch the `opentee-engine`:

    $ /opt/OpenTee/bin/opentee-engine

Verify that Open-TEE is running with `ps`:

    $ ps waux | grep tee

You should see output similar to the example below:

>
> $ ps waux |grep tee
> brian     5738  0.0  0.0  97176   852 ?        Sl   10:40   0:00 tee_manager
> brian     5739  0.0  0.0  25216  1144 ?        S    10:40   0:00 tee_launcher
>

Now launch and attach `gdb` to the `tee_launcher` process:

    $ gdb -ex "set follow-fork-mode child" opentee-engine $(pidof tee_launcher)

The `set follow-fork-mode child` command passed to `gdb` on the command line causes `gdb` to follow children processes across forks in order to drop into the TA process itself and resume execution.

In second terminal run the client application:

    $ /opt/OpenTee/bin/conn_test_app

You should now expect to see output similar to the following:

>
> ./conn_test_app
> START: conn test app
> Initializing context:
>

Back in `gdb` you can now step through and debug the trusted application the `conn_test_app` is connected to. If you continue execution you should see output from the `conn_test_app` similar to the following:

>
> $ ./conn_test_app
> START: conn test app
> Initializing context: initialized
> Openning session: opened
> yyyyyyyyyyyyyyyyyyyyxxxxx
> Invoking command: invoked
> Closing session: Closed
> Finalizing ctx: Finalized
> END: conn test app
>


Options
------

### Command Line Options

The `opentee-engine` executable supports the following command line options:

Usage: `./bin/opentee-engine [OPTION...]`

* `-p`, `--pid-dir=PATH`
  Specify path to keep pid file.
  Defaults to:
  - `/var/run/opentee` when run by root, or
  - `/tmp/opentee when` run by a non-root user.


* `-c`, `--config=FILE`
  Specify path to configuration file.
  Defaults to: `/etc/opentee.conf`


* `-f`, `--foreground`
  Do not daemonize but start the process in foreground.


* `-h`, `--help`
  Print list of command line options.

### Environmental Variables

The following environmental variables control the behaviour of Open-TEE:

* `OPENTEE_SOCKET_FILE_PATH`
  Defines path to socket used for communication between `tee_manager` and `libtee`.
  Defaults to `/tmp/open_tee_sock` on Linux
  Defaults to `/data/local/tmp/open_tee_sock` on Android


* `OPENTEE_STORAGE_PATH`
  Defines directory used for object storage.
  Defaults to `$HOME/.TEE_secure_storage` on Linux
  Defaults to `/data` on Android

FAQ
------

If you get the following error when trying to attach `gdb` to `tee_launcher`:

>
> Could not attach to process.  If your uid matches the uid of the target
> process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
> again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
> ptrace: Operation not permitted.
>

Run the following command and invoke `gdb` again:

    $ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

Contact
------

Bug reports and other issues:
* https://github.com/Open-TEE/project/issues

License
------
