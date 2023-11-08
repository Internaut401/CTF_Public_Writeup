## INSTRUCTION:

We need a Linux enviroment, so if you use  MAC OS or Windows:
- Download virtulization software like (non-free) VMware or (free) VirtualBox 
   https://www.virtualbox.org/wiki/Downloads
- Downloads GNU-Linux ISO image, ultimed realised of Debian/Debian distro are suggested, Ubuntu is highly raccomended for an easy installation
   https://www.ubuntu-it.org/download



- Now from our linux OS, first we need to download and install QEMU (https://www.qemu.org/download/)
   if you have Debian distro like Ubuntu just type from terminal:
   sudo apt-get install qemu
- last thing to download is obviously our QCOW2 image:
   https://exploit.education/downloads/
   version "AMD64 (also i486)"

The installation is automatized by a script so we just need to setup permission 

```sudo chmod +x boot-exploit-education-phoenix-amd64.sh```

and launch the bash script which lunch qemu and if is not present, first install the QCOW2 image and then boot it.

```./boot-exploit-education-phoenix-amd64.sh```

When we want to power on our machine, relaunch the script

Finally we can access to machine by native shell or by SSH:
   ssh -p 2222 user@localhost

username | password
---------|----------
user | user
root | root

To avoid gdb *`UnicodeEncodeError`*:
```
export LC_CTYPE=C.UTF-8
```
