
# Windows development: one time system configuration

Install [Chocolatey](https://chocolatey.org) first

In an Adminstrator powershell:

Install misc utilities:

- `choco install 7zip`

Install Python 3.10:

# These options install into c:\Python310 for all users
- `choco install python --version 3.10.7 --params "'/qn /norestart ALLUSERS=1 TARGETDIR=c:\Python310'"`

Python will install to C:\Python30. Restart the shell to pickup it up.

Run the following:

- `python -m pip install --upgrade pip`
- `python -m pip install --upgrade setuptools`

Install the Microsoft Visual C++ compiler, per https://wiki.python.org/moin/WindowsCompilers:

- `choco install visualstudio2019community`

Then run 'Visual Studio Installer' from the Start menu, and enable the 'Python development' workload, plus the 'Python native development tools' option.

Install cygwin with needed packages:

- `choco install cygwin --params "/InstallDir:C:\cygwin64"`
- `choco install rsync openssh --source=cygwin`

# Windows development: python virtualenv setup

Next, prepare a python virtualenv with all the necessary dependencies. This step can be repeated in fresh clones of the repositories.

From your checkout of steamos-devkit:

- setup: `python -m venv .`
- activate: `.\Scripts\Activate.ps1`

    If you get an `UnauthorizedAccess` error due to [execution policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies), run the following command first: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

Start by updating base tools:

- `python -m pip install --upgrade pip`
- `python -m pip install --upgrade setuptools`

Install project dependencies:

- `pip install -r requirements.txt`

Install the pyimgui wheel:

- `pip install .\pyimgui-wheels\imgui-2.0.0-cp310-cp310-win_amd64.whl`

You are ready for development. The application can be started by running `python .\devkit-gui.py` in the client/ directory.

# Windows packaging:

From the activated virtual env:

- `python .\setup\package-windows.py`

# Linux development:

We recommended a system with Python 3.9 or 3.10 (Arch and derivatives, or Ubuntu 20.x or newer)

Instructions below use [pipenv](https://pipenv.pypa.io/en/latest/), but can be adapted to any other python virtual environment solution.

- `pipenv shell`
- `pip install -r requirements.txt`
- `pip install ./pyimgui-wheels/imgui-2.0.0-cp310-cp310-linux_x86_64.whl`

(Assuming you are on a Python 3.10 system, see wheels documentation below)

- `cd client`
- `./devkit-gui.py`

# Linux packaging for distribution:

## One time setup:

From a blank Ubuntu 18 (bionic) VM, or via toolbox, podman, docker etc.:

Installing 3.9 and 3.10 backports from https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa

As root:

```text
$ add-apt-repository ppa:deadsnakes/ppa
$ apt-get update
$ apt-get upgrade
$ apt-get install gcc python3.9 python3.9-dev python3.9-distutils python3.10 python3.10-dev python3.10-distutils
```

Boostrapping pip and pipenv.

As user:

```text
$ wget https://bootstrap.pypa.io/get-pip.py
$ python3.9 ./get-pip.py
$ python3.9 -m pip install pipenv
$ python3.10 ./get-pip.py
$ python3.10 -m pip install pipenv
```

## Package:

- Fresh git clone
- `python3.9 -m pipenv --python 3.9 shell`
- `pip install -r requirements.txt`
- `pip install pyimgui-wheels/imgui-2.0.0-cp39-cp39-linux_x86_64.whl`
- `./setup/package-linux.py`

Repeat for Python 3.10

# Building a Windows pyimgui wheel:

We keep a ready to use .whl file in the repository, so this step is normally not needed.

Steps provided here as a reference if the wheel needs to be updated:

- git clone `https://github.com/pyimgui/pyimgui`, to branch `dev/version-2.0`
- setup a python virtualenv: `python -m venv C:\pyimgui`
- activate `.\Scripts\activate.ps1`

(replace `C:\pyimgui` with the path to your pyimgui repository)

Look at the Makefile and follow the 'make build' flow (alternatively, install make via cygwin or msys and run 'make build'):

- `git submodule update --init`
- `pip install -r doc/requirements-dev.txt`
- `python -m pip install -e . -v`

Produce a wheel (in dist/):

- `python .\setup.py bdist_wheel`

# Building Linux pyimgui wheels:

We keep ready to use wheels for Python 3.9 and Python 3.10 in the repository, built against Ubuntu 18 to best ABI compatibility.

Use a ubuntu 18.04 vm to have good backwards compatibility with glibc. But there are some manual steps required since it doesn't have python3.9 or 3.10.

First add the deadsnakes repo and remove python3.6 setuptools that will get in the way:

- `sudo apt-add-repository ppa:deadsnakes/ppa`
- `sudo apt-get purge python3-setuptools`

Then you need a couple of packages:

- `sudo apt-get install python3.9 python3.9-distutils python3.9-stdlib`

Then you need pip, but there's no python3.9-pip package so use this:

- `curl https://bootstrap.pypa.io/get-pip.py -o ~/get-pip.py`
- `python3.9 ~/get-pip.py`

This makes a pip and pip3 in ~/.local/bin but doesn't add that to your PATH, so add it manually or run with absolute path, etc.

- `export PATH=~/.local/bin:$PATH`

Then install pipenv using pip:

- `pip install pipenv`

Then build the cp39 wheel:

- `make -f ./ci.mk`

Wheel will be in dist folder so copy to steamos-devkit/pyimgui-wheels/ for commit.

Then to build the python 3.10 wheel you need to clean up some things from the above:

- `sudo apt purge python3.9 python3.9-distutils python3.9-stdlib`
- `rm -fR ~/.local/bin/p*`
- `rm -fR ~/.local/share/virtualenvs/pyimgui*`

Then install python 3.10 packages:

- `sudo apt-get install python3.10 python3.10-distutils python3.10-stdlib`

Then rerun the get-pip.py script from above:

- `python3.10 ~/get-pip.py`

Then install pipenv for python 3.10:

- `pip install pipenv`

Then build the cp310 wheel:

- `git clean -xfd`
- `make -f ./ci.mk`

Then copy the cp310 wheel into steamos-devkit/pyimgui-wheels/ for commit.
