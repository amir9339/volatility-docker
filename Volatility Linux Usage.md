***This method was tested on Ubuntu, may work on Debian as well***

#### Obtaining a System Map

Obtain the file `/boot/System.map-xxxx` where `xxxx` is the kernel version (obtainable by `uname -r`).

#### Obtaining Debug Symbols

Debug symbols for the specific kernel version can be obtained on Ubuntu the following way:

```bash
# set up apt for obtaining debug symbol packages
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list

# obtain the signing key for the symbol packages
sudo apt install ubuntu-dbgsym-keyring
# for releases earlier than Ubuntu 18.04 use:
# sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622

# update apt
sudo apt update

# obtain debugging symbols for the kernel (you may replace `uname -r` with the specific kernel version you need)
sudo apt install linux-image-`uname -r`-dbgsym # this will start a very large download
```

If an error occurs, try installing this package manually:
```bash
wget http://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-$(uname -r)-dbgsym_$(uname -r).41_amd64.ddeb
sudo dpkg -i linux-image-unsigned-$(uname -r)-dbgsym_$(uname -r).41_amd64.ddeb
```

After following these steps, a kernel image with debugging symbols should be placed at `/usr/lib/debug/boot/vmlinux-xxxx` where `xxxx` is the kernel version.

#### Building a Profile

To build a profile, the tool **dwarf2json** will be used to convert the system map file and the debug symbols file into a single JSON file.

```bash
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json

# Some GO versions require:
go get github.com/spf13/pflag

go build # make sure go is installed first
./dwarf2json linux --system-map System.map-xxxx --elf vmlinux-xxxx > outfile.json # give the output file an appropriate name like Ubuntu-5.4.0-88-generic-Profile.json
```

After obtaining the JSON file, place it under `volatility3/volatility3/framework/symbols/linux`.

You can check if the symbol table is validated using:

```
python3 vol.py isfinfo
```

#### Obtaining a Memory Dump

The best method to obtain a full memory dump is using LiME. LiME needs to be built on a machine identical in kernel version and distro release to the one that it will be used on.

```bash
# build LiME from a release
wget https://github.com/504ensicsLabs/LiME/archive/refs/tags/v1.9.1.tar.gz -O LiME-1.9.1.tar.gz
tar -xzf LiME-1.9.1.tar.gz
cd LiME-1.9.1/src
make # this will create a file lime-xxxx.ko where 'xxxx' is the kernel version

# or from the repo:
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src/
make
reboot # you might need to restart the machine before loading LiME, reboot only if you need it

# obtain a memory dump - replace 'xxxx' with the kernel version and the path with the desired output path
sudo insmod lime-xxxx.ko "path=/tmp/dumpfile.lime format=lime"
```

#### Volatility Usage

Once the profile has been created and installed in the correct directory, we can analyze memory dumps from the machine we built the profile for as following:

`python3 vol.py -f dumpfile.lime <plugin>`. Available plugins can be listed using `python3 vol.py -h`.