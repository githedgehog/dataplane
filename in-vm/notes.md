# Running tests in containers / vms

## VM setup

### Schedule of events to launch test in micro vm

First, we are going to wrap the vm in a user specified container.
We ignore any user provided cmd / entrypoint and instead run our own container phase init binary sourced from a volume we have provided (let's assume it is mounted at /run/testin/tools)
Additionally, we need an empty mount point (maybe a tmpfs) at an agreed upon location.  Let's call it `/run/testin/new_root`.
Further, we need to transform any user provided volume mounts / bind mounts / tmpfs mounts to be prefixed by /run/testing/volumes.

Now, we run the init binary.

* The init binary _non-recursively_ bind mounts (in private mode), the whole / filesystem to `/run/testin/new_root`.
* We then move the mount points of `/run/testin/volumes` to their respective locations in `/run/testin/new_root`.
* At this point we have the following tools available
  * /run/testin/tools/cloud-hypervisor (static compile)
  * /run/testin/tools/virtiofsd (static compile)
  * /run/testin/tools/container-init (static compile)
  * /run/testin/tools/bzImage (kernel)
  * /run/testin/tools/initrd.cpio
    * /init
    * /nix/...
    * /proc
    * /sys
    * /dev
    * /run
    * /tmp
    * /new_root


I think the directory structure we need to build in our volume is as follows

* < container-init >
  * container-init (static)
  * cloud-hypervisor (static)
  * virtiofsd (static)
  * boot/
    * bzImage (linux kernel)
  * vhost/ (may be bind mounted back to user directory to facilitate debugging)
  * initfs/ (will be base of virtiofsd)
    * init (static)
    * proc/ (empty)
    * sys/ (empty)
    * dev/ (empty)
    * new_root/ (bound from user specified container)
      * proc/ (empty)
      * sys/ (empty)
      * dev/ (empty)
      * run/ (empty)

Then we start with

* < user specified container >
  * /testin <-- volume or bind mount of < container-init >

Then we set the entrypoint to /testin/container-init and run the container

### Incremental development plan

* some basic version of the vm init is done.
* we can launch a vm with a kernel and initrd
* virtiofsd sharing (needs uid/gid squash and maybe xattrs `security.` mapping)

* do we need some kind of test runner script / bin in the vm?  Maybe I can work around setting caps on the test binaries by having caps get selectively inherited from the vm init somehow.


Also, we need to think through the basic "run in a container use case"

Can I just bind mount the test binary and use that as the entrypoint?  That seems like a solid place to start.

Yeah, that worked.

Now for the vm part.

* < container-init >
  * container-init (old in-vm bin)
  * nix/ (from libc env)
  * bin/cloud-hypervisor (static)
  * bin/virtiofsd (static)
  * bzImage (linux kernel)
  * vhost/ (may be bind mounted back to user directory to facilitate debugging)
  * initfs/ (libc initrd like)
    * init (static)
    * proc/ (empty)
    * sys/ (empty)
    * dev/ (empty)
    * nix/ (from libc env)
    * run/
    * tmp/
    * ...self...

ok, basically I need to make a libc initrd, at least for the moment.
