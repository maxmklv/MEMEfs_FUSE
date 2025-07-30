# Makefile for MEMEfs

# Binaries
MEMEFS     := memefs
MKMEMEFS   := mkmemefs

# Source files
MEMEFS_SRC := memefs.c
MKMEMEFS_SRC := mkmemefs.c

# Mount and image paths
MOUNT_DIR  := /tmp/memefs
IMG_FILE   := myfilesystem.img
VOLUME_NAME := MYVOLUME

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -D_FILE_OFFSET_BITS=64
LDFLAGS := -lfuse3

.PHONY: all build run debug clean create_dir unmount_memefs mount_memefs create_memefs_img

all: build

build: build_memefs build_mkmemefs

build_memefs: $(MEMEFS_SRC)
	$(CC) $(CFLAGS) -o $(MEMEFS) $(MEMEFS_SRC) $(LDFLAGS)

build_mkmemefs: $(MKMEMEFS_SRC)
	$(CC) $(CFLAGS) -o $(MKMEMEFS) $(MKMEMEFS_SRC)

create_dir:
	mkdir -p $(MOUNT_DIR)

unmount_memefs:
	sudo fusermount -u $(MOUNT_DIR) || true

mount_memefs: build create_dir
	./$(MEMEFS) $(IMG_FILE) $(MOUNT_DIR)

debug: build create_dir
	./$(MEMEFS) $(IMG_FILE) $(MOUNT_DIR) -f -d

create_memefs_img: build_mkmemefs
	./$(MKMEMEFS) $(IMG_FILE) "$(VOLUME_NAME)"

clean:
	rm -f $(MEMEFS) $(MKMEMEFS) $(IMG_FILE)
