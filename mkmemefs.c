/*
    mkmemefs.c

    Filesystem image creation tool for the Multimedia Embedded Memory
    Encapsulation Filesystem.

    Copyright (C) 2020 Lawrence Sebald

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    3. Neither the name of the copyright holder nor the names of its
       contributors may be used to endorse or promote products derived from this
       software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

    // Structure representing the superblock metadata for the filesystem.
    typedef struct memefs_superblock
{
    char signature[16];        // Filesystem signature
    uint8_t cleanly_unmounted; // Flag for unmounted state
    uint8_t reseerved1[3];     // Reserved bytes
    uint32_t fs_version;       // Filesystem version
    uint8_t fs_ctime[8];       // Creation timestamp in BCD format
    uint16_t main_fat;         // Starting block for main FAT
    uint16_t main_fat_size;    // Size of the main FAT
    uint16_t backup_fat;       // Starting block for backup FAT
    uint16_t backup_fat_size;  // Size of the backup FAT
    uint16_t directory_start;  // Starting block for directory
    uint16_t directory_size;   // Directory size in blocks
    uint16_t num_user_blocks;  // Number of user data blocks
    uint16_t first_user_block; // First user data block
    char volume_label[16];     // Volume label
    uint8_t unused[448];       // Unused space for alignment
} __attribute__((packed)) memefs_superblock_t;

// Buffer for holding data blocks to be written to the filesystem image.
static uint8_t block_buf[512];

// Writes a 512-byte block to a file descriptor.
static inline int write_block(int fd)
{
    return write(fd, block_buf, 512) != 512;
}

// Clears the block buffer by setting all bytes to zero.
static inline void clear_block_buf(void)
{
    memset(block_buf, 0, 512);
}

// Encodes an integer as packed binary-coded decimal (BCD).
static inline uint8_t pbcd(uint8_t num)
{
    uint8_t a = num % 10, b = num / 10;
    return b <= 9 ? ((b << 4) | a) : 0xFF;
}

// Fills the superblock structure with metadata, including the volume label.
static void fill_superblock(const char *volname)
{
    memefs_superblock_t *sb = (memefs_superblock_t *)block_buf;
    time_t now = time(NULL);
    struct tm ts;

    gmtime_r(&now, &ts); // Gets the current time in UTC format.

    clear_block_buf();                             // Initializes block buffer to zero.
    memcpy(sb->signature, "?MEMEFS++CMSC421", 16); // Sets filesystem signature.
    sb->fs_version = htonl(1);                     // Sets filesystem version in network byte order.

    // Fills BCD-encoded creation time.
    sb->fs_ctime[0] = pbcd((ts.tm_year + 1900) / 100);
    sb->fs_ctime[1] = pbcd(ts.tm_year % 100);
    sb->fs_ctime[2] = pbcd(ts.tm_mon + 1);
    sb->fs_ctime[3] = pbcd(ts.tm_mday);
    sb->fs_ctime[4] = pbcd(ts.tm_hour);
    sb->fs_ctime[5] = pbcd(ts.tm_min);
    sb->fs_ctime[6] = pbcd(ts.tm_sec);

    // Sets FAT and directory metadata fields.
    sb->main_fat = htons(254);
    sb->main_fat_size = htons(1);
    sb->backup_fat = htons(239);
    sb->backup_fat_size = htons(1);
    sb->directory_start = htons(253);
    sb->directory_size = htons(14); 
    sb->num_user_blocks = htons(220);
    sb->first_user_block = htons(1);

    if (volname)
        strncpy(sb->volume_label, volname, 16); // Sets volume label if provided.
}

// Fills the FAT block with initial values, including reserved and user blocks.
static void fill_blank_fat(void)
{
    int i;
    uint16_t *fat = (uint16_t *)block_buf;

    clear_block_buf(); // Resets block buffer to zero.
    fat[0] = 0xFFFF;   // Marks FAT entries as reserved.
    fat[239] = 0xFFFF;
    fat[240] = 0xFFFF;
    fat[254] = 0xFFFF;
    fat[255] = 0xFFFF;

    // Chains FAT entries from 241 to 253.
    for (i = 241; i < 254; ++i)
    {
        fat[i] = htons(i - 1);
    }
}

// Writes the initialized FAT block to the image file.
static int write_fat(int fd)
{
    fill_blank_fat(); // Prepares the FAT entries.

    // Writes the main FAT.
    if (lseek(fd, 254 * 512, SEEK_SET) < 0)
    {
        perror("fseek");
        return -1;
    }
    if (write_block(fd))
    {
        perror("write_block");
        return -1;
    }

    // Writes the backup FAT.
    if (lseek(fd, 239 * 512, SEEK_SET) < 0)
    {
        perror("fseek");
        return -1;
    }
    if (write_block(fd))
    {
        perror("write_block");
        return -1;
    }

    return 0;
}

// Writes the superblock to the start and end locations in the image file.
static int write_superblock(int fd, const char *volname)
{
    fill_superblock(volname); // Populates superblock metadata.

    // Writes the superblock at the end of the file system.
    if (lseek(fd, 255 * 512, SEEK_SET) < 0)
    {
        perror("fseek");
        return -1;
    }
    if (write_block(fd))
    {
        perror("write_block");
        return -1;
    }

    // Writes the superblock at the beginning of the filesystem.
    if (lseek(fd, 0 * 512, SEEK_SET) < 0)
    {
        perror("fseek");
        return -1;
    }
    if (write_block(fd))
    {
        perror("write_block");
        return -1;
    }

    return 0;
}

// Copies a file from source to destination in 512-byte chunks.
static int copy_file(const char *src, const char *dst)
{
    FILE *sfp, *dfp;

    if (!(sfp = fopen(src, "rb")))
    {
        perror("copy_file");
        return -1;
    }

    if (!(dfp = fopen(dst, "wb")))
    {
        perror("copy_file");
        fclose(sfp);
        return -1;
    }

    while (fread(block_buf, 1, 512, sfp) == 512)
    {
        if (fwrite(block_buf, 1, 512, dfp) != 512)
        {
            perror("copy_file");
            fclose(dfp);
            fclose(sfp);
            unlink(dst); // Removes partially written destination file on error.
            return -1;
        }
    }

    fclose(dfp);
    fclose(sfp);
    return 0;
}

// Main function for creating a filesystem image file.
int main(int argc, char *argv[])
{
    int fd;
    char tmpfn[64];

    // Ensures the correct number of arguments are provided.
    if (argc < 2 || argc > 3)
    {
        if (argc > 0)
            printf("Usage: %s image_filename [vol_name]\n", argv[0]);
        else
            printf("Usage: mkmemefs image_filename [vol_name]\n");
        return 1;
    }

    strcpy(tmpfn, "/tmp/mkmemefsXXXXXX");

    // Creates a temporary file.
    if ((fd = mkstemp(tmpfn)) < 0)
    {
        perror("mkstemp");
        return 1;
    }

    // Sets the size of the file to 256 blocks (512 bytes each).
    if (ftruncate(fd, 256 * 512))
    {
        perror("ftruncate");
        close(fd);
        unlink(tmpfn);
        return 1;
    }

    // Writes the superblock data to the image file.
    if (write_superblock(fd, argc == 3 ? argv[2] : NULL))
    {
        close(fd);
        unlink(tmpfn);
        return 1;
    }

    // Writes the FAT to the image file.
    if (write_fat(fd))
    {
        close(fd);
        unlink(tmpfn);
        return -1;
    }

    close(fd);

    // Renames the temporary file to the desired output filename.
    if (rename(tmpfn, argv[1]))
    {
        if (errno == EXDEV)
        {
            // If rename fails, attempts to copy the file instead.
            if (!copy_file(tmpfn, argv[1]))
            {
                unlink(tmpfn);
                return 0;
            }
        }
        perror("rename");
        unlink(tmpfn);
        return 1;
    }

    return 0;
}