# MEMEfs — A Custom FUSE Filesystem

This project focuses on the design and implementation of filesystems, using Multimedia Embedded Memory Encapsulation (MEMEfs) as the demostration of this concept. The MEMEfs format consists of the following:

-Volume Size: 128 KiB( (256 blocks, each 512 bytes) 

-File Allocation Table (FAT): single-level directory structure

-Superblocks: main and backup

-Permissions Model 

The project is split into Part 1: user-space Read-Only filesystem using Filesystem in Userspace (FUSE) framework, and Part 2: user-space Read-and-Write FUSE framework.
## How to Build?
You've been provided a Makefile. If you need to change something, please document it here. Otherwise read the following instructions.

The following will run you through how to compile and fuse setup:

<!-- NOTE: below is how you represent a code block in markdown! -->
```bash
# Step 1: Compile mkmemefs

make build_mkmemefs

# Step 2: Run mkmemefs to create an memefs image

./mkmemefs <image_filename> <volume-name>

# Step 3: Create Test Dir (under /tmp). Note that this dir only needs to be created once. DO NOT PULL FILES IN THIS DIR (IT NEEDS TO REMAIN EMPTY). YOU'VE BEEN WARNED. 

make create_dir

# Step 4: Mount the Filesystem

make build_memefs
make mount_memefs

# Step 5: Unmount the Filesystem

make unmount_memefs

```


# Explain the Build Process

The build process starts off with building mkmemefs so it can create the filesystem image. After being built the mkmemefs is ran with the paramenters of the image name and volume name. The next step is to create a directory in /tmp to be the mount point for the filesystem. The directory must remain empty. Before mounting the filesystem memefs is compiled to set up the FUSE. With FUSE ready the filesystem is mounted with the compiled memefs to the test directory. After this process the filesystem is available for file creation, write, append, and delete. When finished with filesystem or in case there is a need to restart, it MUST be unmounted before attempting to mount again to the test directory;

# Explain Memefs Source Code

The source code starts with the structures of the superblock, which is identical to that in mkmemefs, as well as the directory entry. These two structures are called in most operations whether to provide information on the elements of the filesystem or to modify it.

Next the helper functions are declared first to prevent uninitialized declarations within operations functions. The helpers include the load_superblock and load directory functions described in the project doc, as well as the provited bcd functions from the doc. 

Helpers are followed by the operations that needed to be implemented: .getattr, .readdir, .open, .read, .create, .write, .truncate, and .unlink. The first 4 were initally implemented with Part Read_only in mind, and were appropriately modified for Part 2 to work with write functionality. The next 4 were implemented as Part 2, with .create including more testing error messages as it was necessary to verify the remaining functions. 

They are followed by the main functional identical to the example function in the project doc. With it being in this format, using ./memefs <your-filesystem.img> <mount-point> -f -d, allowed for debugging that pushed the code functionality to perform as intended after  many initial errors and bugs.

# References
[IBM: l-fuse](https://developer.ibm.com/articles/l-fuse/)

[github: hello.c] (https://github.com/libfuse/libfuse/blob/master/example/hello.c)

[kernel.org: FUSE] (https://docs.kernel.org/filesystems/fuse.html)

## Authors
Maxim Mikhaylov
- [GitHub](https://www.github.com/maxmklv/MEMEfs_FUSE)
