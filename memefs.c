#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> 
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h> 
#include <arpa/inet.h>

#define BLOCK_SIZE 512
#define MAX_DIR_ENTRIES 224 
#define MEMEFS_SIGNATURE "?MEMEFS++CMSC421"
#define DIRECTORY_BLOCK_START 240
#define DIRECTORY_BLOCK_SIZE 14
#define SUPERBLOCK_BACKUP 0
#define SUPERBLOCK_MAIN 255
#define FAT_BLOCK_SIZE 256 
#define MAX_FILENAME_LEN 11

int img_fd = -1;

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

typedef struct memefs_dirent {
    uint16_t type_and_permission;    // File type and permission bits
    uint16_t start_block;            // Location of the first block of the file
    uint8_t filename[11];            // 8.3 style filename
    uint8_t unused;                  // Unused
    uint8_t bcd_timestamp[8];        // Last write timestamp in BCD format
    uint32_t file_size;              // File size
    uint16_t owner_uid;              // Owner user ID
    uint16_t group_gid;              // Group GID
} __attribute__((packed)) memefs_dirent_t;


memefs_superblock_t superblock;
memefs_dirent_t directory[MAX_DIR_ENTRIES];

uint16_t fat_table[FAT_BLOCK_SIZE];

/******** TEMPORARY ********/
//static const char* filepath = "/hello.txt";
//static const char* filename = "hello.txt";
//static const char* filecontent = "Hello World!\n";

/****** HELPERS ******/
int load_superblock() {
    if (img_fd < 0) return -EBADF;

    memefs_superblock_t sb_main, sb_backup;

    // Read sb_main superblock
    if (lseek(img_fd, SUPERBLOCK_MAIN * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (read(img_fd, &sb_main, sizeof(sb_main)) != sizeof(sb_main)) {
        return -EIO;
    }

    // Read backup superblock
    if (lseek(img_fd, SUPERBLOCK_BACKUP * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (read(img_fd, &sb_backup, sizeof(sb_backup)) != sizeof(sb_backup)) {
        return -EIO;
    }
    // Check both have valid signatures
    if (strncmp(sb_main.signature, MEMEFS_SIGNATURE, strlen(MEMEFS_SIGNATURE)) != 0 || strncmp(sb_backup.signature, MEMEFS_SIGNATURE, strlen(MEMEFS_SIGNATURE)) != 0) {
        return -EINVAL;
    }

    // Check both copies are identical
    if (memcmp(&sb_main, &sb_backup, sizeof(sb_main)) != 0) {
        return -EINVAL;
    }

    sb_main.main_fat = ntohs(sb_main.main_fat);
    sb_main.main_fat_size = ntohs(sb_main.main_fat_size);
    sb_main.backup_fat = ntohs(sb_main.backup_fat);
    sb_main.backup_fat_size = ntohs(sb_main.backup_fat_size);
    sb_main.directory_start = ntohs(sb_main.directory_start);
    sb_main.directory_size = ntohs(sb_main.directory_size);
    sb_main.num_user_blocks = ntohs(sb_main.num_user_blocks);
    sb_main.first_user_block = ntohs(sb_main.first_user_block);

    // Check for sane values 
    if (sb_main.main_fat == 0 || sb_main.main_fat_size == 0 || sb_main.backup_fat == 0 || sb_main.backup_fat_size == 0) {
        return -EINVAL;
    }
    if (sb_main.directory_start == 0 || sb_main.directory_size == 0) {
        return -EINVAL;
    }
    if (sb_main.num_user_blocks == 0 || sb_main.first_user_block == 0) {
        return -EINVAL;
    }

    // Check the volume label (not empty)
    if (strlen(sb_main.volume_label) == 0) {
        return -EINVAL;
    }

    // Check for clean unmounting 
    if (sb_main.cleanly_unmounted > 1) {
        return -EINVAL;
    }

    // All checks passed; store to global
    memcpy(&superblock, &sb_main, sizeof(superblock));

    return 0;
}

int load_directory() {
    // Check that the image file is open
    if (img_fd < 0) {
        perror("Error opening image file");
        return -EBADF;
    }

    // Check directory region size
    size_t total_dir_bytes = superblock.directory_size * BLOCK_SIZE; // reference the number of bytes loading the correct size takes up
    if (total_dir_bytes % sizeof(memefs_dirent_t) != 0) {
        fprintf(stderr, "Error: Directory region size is not a multiple of the directory entry size. Total size: %zu, Directory entry size: %zu\n",
            total_dir_bytes, sizeof(memefs_dirent_t));
        return -EINVAL;
    }

    // Check directory entry count
    int entry_count = total_dir_bytes / sizeof(memefs_dirent_t);
    if (entry_count > MAX_DIR_ENTRIES) {
        fprintf(stderr, "Error: Directory entry count exceeds the maximum allowed. Entry count: %d, Max entries: %d\n",
            entry_count, MAX_DIR_ENTRIES);
        return -E2BIG;
    }
    // Allocate memory for the directory buffer
    memefs_dirent_t* temp = malloc(total_dir_bytes);
    if (temp == NULL) {
        perror("Failed to allocate memory for directory buffer");
        return -ENOMEM;
    }

    // Check read success
    size_t bytes_read = 0;
    char* buf = (char*)temp;
    while (bytes_read < total_dir_bytes) {
        ssize_t res = read(img_fd, buf + bytes_read, total_dir_bytes - bytes_read);
        if (res < 0) {
            perror("Error reading directory region");
            free(temp);
            return -EIO;
        }
        else if (res == 0) {
            fprintf(stderr, "Unexpected EOF. Bytes read: %zu, Expected: %zu\n", bytes_read, total_dir_bytes);
            free(temp);
            return -EIO;
        }
        bytes_read += res;
    }

    memcpy(directory, temp, total_dir_bytes);
    free(temp);
    return 0;
}

uint8_t to_bcd(uint8_t num) {
    if (num > 99) return 0xFF;
    return ((num / 10) << 4) | (num % 10);
}

void generate_memefs_timestamp(uint8_t bcd_time[8]) {
    time_t now = time(NULL);
    struct tm utc;
    gmtime_r(&now, &utc); // UTC time (MEMEfs uses UTC, not localtime)

    int full_year = utc.tm_year + 1900;
    bcd_time[0] = to_bcd(full_year / 100); 	// Century
    bcd_time[1] = to_bcd(full_year % 100); 	// Year within century
    bcd_time[2] = to_bcd(utc.tm_mon + 1);  	// Month (0-based in tm)
    bcd_time[3] = to_bcd(utc.tm_mday);     	// Day
    bcd_time[4] = to_bcd(utc.tm_hour);     	// Hour
    bcd_time[5] = to_bcd(utc.tm_min);      	// Minute
    bcd_time[6] = to_bcd(utc.tm_sec);      	// Second
    bcd_time[7] = 0x00;                         	// Unused (reserved)
}

/****** OPERATIONS ******/
int memefs_getattr(const char* path, struct stat* buf, struct fuse_file_info* fi) {  // Retrieves file attributes, the metadata (permissions, size, timestamps).
    (void)fi;

    memset(buf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        buf->st_mode = S_IFDIR | 0755; // rwx r-x x 
        buf->st_nlink = 2;
        return 0;
    }
    if (load_directory() < 0) {
        return -EIO;
    }

    const char* target = path + 1; // Skip leading '/'
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] == 0x00 || directory[i].filename[0] == 0xE5) continue;

        char fname[MAX_FILENAME_LEN + 1] = { 0 };
        memcpy(fname, directory[i].filename, MAX_FILENAME_LEN);
        fname[MAX_FILENAME_LEN] = '\0';

        if (strncmp(fname, target, MAX_FILENAME_LEN) == 0) {
            buf->st_mode = S_IFREG | (directory[i].type_and_permission & 0777);
            buf->st_nlink = 1;
            buf->st_size = directory[i].file_size;
            buf->st_uid = directory[i].owner_uid;
            buf->st_gid = directory[i].group_gid;
            return 0;
        }
    }

    return -ENOENT;
}

int memefs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info* fi, enum fuse_readdir_flags flags) { // List directory contents
    (void)off;
    (void)fi;
    (void)flags;

    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }

    if (load_directory() < 0) {
        return -EIO;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (directory[i].type_and_permission != 0xFFFF) {
            char name[MAX_FILENAME_LEN + 1];
            memcpy(name, directory[i].filename, MAX_FILENAME_LEN);
            name[MAX_FILENAME_LEN] = '\0';
            filler(buf, name, NULL, 0, 0);
        }
    }

    return 0;
}

int memefs_open(const char* path, struct fuse_file_info* fi) { // Validate file existence and open it.
    if (load_directory() < 0) {
        return -EIO;
    }

    const char* target = path + 1;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] == 0x00 || directory[i].filename[0] == 0xE5) continue;

        char fname[MAX_FILENAME_LEN + 1] = { 0 };
        memcpy(fname, directory[i].filename, MAX_FILENAME_LEN);
        fname[MAX_FILENAME_LEN] = '\0';

        if (strncmp(fname, target, MAX_FILENAME_LEN) == 0) {
            if ((fi->flags & O_ACCMODE) != O_RDONLY) {
                return -EACCES;
            }
            return 0;
        }
    }

    return -ENOENT;
}

int memefs_read(const char* path, char* buf, size_t size, off_t off, struct fuse_file_info* fi) { // Read data from an open file descriptor.
    (void)fi;

    if (load_directory() < 0) {
        return -EIO;
    }

    const char* target = path + 1;
    memefs_dirent_t* entry = NULL;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] == 0x00 || directory[i].filename[0] == 0xE5) continue;

        char fname[MAX_FILENAME_LEN + 1] = { 0 };
        memcpy(fname, directory[i].filename, MAX_FILENAME_LEN);
        fname[MAX_FILENAME_LEN] = '\0';

        if (strncmp(fname, target, MAX_FILENAME_LEN) == 0) {
            entry = &directory[i];
            break;
        }
    }

    if (!entry) {
        return -ENOENT;
    }

    if (entry->start_block == 0 || entry->file_size == 0) {
        return 0; // Empty file
    }

    // Load FAT table
    lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET);
    read(img_fd, fat_table, sizeof(fat_table));

    size_t to_read = size;
    if (off >= entry->file_size) return 0;
    if (off + size > entry->file_size) to_read = entry->file_size - off;

    size_t bytes_read = 0;
    uint16_t current_block = entry->start_block;
    size_t block_offset = off / BLOCK_SIZE;
    size_t inner_offset = off % BLOCK_SIZE;

    // Traverse to the offset block
    for (size_t i = 0; i < block_offset && current_block != 0xFFFF; ++i) {
        current_block = fat_table[current_block];
    }

    while (to_read > 0 && current_block != 0xFFFF) {
        char block[BLOCK_SIZE];
        lseek(img_fd, (superblock.first_user_block + current_block) * BLOCK_SIZE, SEEK_SET);
        read(img_fd, block, BLOCK_SIZE);

        size_t copy_start = (bytes_read == 0) ? inner_offset : 0;
        size_t available = BLOCK_SIZE - copy_start;
        size_t copy_size = (to_read < available) ? to_read : available;

        memcpy(buf + bytes_read, block + copy_start, copy_size);

        bytes_read += copy_size;
        to_read -= copy_size;

        current_block = fat_table[current_block];
    }

    return bytes_read;
}

int memefs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)fi;

    // Load directory
    lseek(img_fd, superblock.directory_start * BLOCK_SIZE, SEEK_SET);
    read(img_fd, directory, sizeof(directory));

    // Find free directory entry
    memefs_dirent_t* new_entry = NULL;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] == 0x00) { // Unused entry
            new_entry = &directory[i];
            break;
        }
    }
    if (!new_entry) {
        return -ENOSPC;
    }

    // Load FAT
    lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET);
    read(img_fd, fat_table, sizeof(fat_table));

    // Reserve a block in the FAT for the file's data if necessary
    uint16_t fat_block = 0;
    for (uint16_t i = 1; i < FAT_BLOCK_SIZE; ++i) {
        if (fat_table[i] == 0x0000) {
            fat_table[i] = 0xFFFF;
            fat_block = i;
            break;
        }
    }
    if (fat_block == 0) {
        return -ENOSPC;
    }

    // Set up initial file metadata (e.g., size = 0, timestamps)
    memset(new_entry, 0, sizeof(memefs_dirent_t));
    strncpy((char*)new_entry->filename, path + 1, MAX_FILENAME_LEN); // skip '/'
    new_entry->start_block = fat_block;
    new_entry->type_and_permission = mode;
    new_entry->file_size = 0;
    new_entry->owner_uid = getuid();
    new_entry->group_gid = getgid();

    // Generate BCD timestamp
    uint8_t bcd_time[8];
    generate_memefs_timestamp(bcd_time); // assumes implementation exists
    memcpy(new_entry->bcd_timestamp, bcd_time, 8);

    // Write updated FAT
    lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET);
    write(img_fd, fat_table, sizeof(fat_table));

    // Write updated directory
    lseek(img_fd, superblock.directory_start * BLOCK_SIZE, SEEK_SET);
    write(img_fd, directory, sizeof(directory));

    return 0;
}

int memefs_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
    (void)fi;

    // Check that the image file is open
    if (img_fd < 0) {
        return -EBADF;
    }

    // Find the file in the directory
    memefs_dirent_t* file_entry = NULL;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] != 0 && strcmp((char*)directory[i].filename, path + 1) == 0) {
            file_entry = &directory[i];
            break;
        }
    }

    // If the file does not exist, return ENOENT
    if (!file_entry) {
        return -ENOENT;
    }

    // Load FAT
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }

    if (read(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Check if the file's start block is valid
    if (file_entry->start_block == 0) {
        return -EINVAL;
    }

    uint16_t current_block = file_entry->start_block;
    off_t file_offset = 0;

    // Traverse the FAT chain to find where to start writing
    while (current_block != 0xFFFF && file_offset < off) {
        // Calculate the offset within the current block
        size_t block_size = BLOCK_SIZE;
        if (file_offset + block_size <= off) {
            file_offset += block_size;
            current_block = fat_table[current_block];
        }
        else {
            break;
        }
    }

    // Now write the data to the appropriate blocks
    off_t bytes_written = 0;
    while (bytes_written < size) {
        if (current_block == 0xFFFF) {
            // No more space, need to allocate a new block
            uint16_t new_block = 0;
            for (uint16_t i = 1; i < FAT_BLOCK_SIZE; ++i) {
                if (fat_table[i] == 0x0000) {
                    fat_table[i] = 0xFFFF;
                    new_block = i;
                    break;
                }
            }
            if (new_block == 0) {
                return -ENOSPC; // No more space on the FAT
            }

            // Allocate the new block in the FAT
            fat_table[current_block] = new_block;
            current_block = new_block;
        }

        // Seek to the correct position in the image file and write data
        if (lseek(img_fd, current_block * BLOCK_SIZE, SEEK_SET) < 0) {
            return -EIO;
        }

        size_t remaining = size - bytes_written;
        size_t block_space = BLOCK_SIZE - (file_offset % BLOCK_SIZE);
        size_t to_write = remaining < block_space ? remaining : block_space;

        // Write the data to the current block
        if (write(img_fd, buf + bytes_written, to_write) != to_write) {
            return -EIO;
        }

        bytes_written += to_write;
        file_offset += to_write;

        // If we've written all the data, we are done
        if (bytes_written == size) {
            // Update file size in the directory entry
            file_entry->file_size = off + size;
            break;
        }
    }

    // Write updated FAT table back to the image
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (write(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Write updated directory back to the image
    if (lseek(img_fd, superblock.directory_start * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (write(img_fd, directory, sizeof(directory)) != sizeof(directory)) {
        return -EIO;
    }

    return size; // Return number of bytes written
}

int memefs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    (void)fi;

    // Find the file in the directory
    memefs_dirent_t* file_entry = NULL;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] != 0 && strcmp((char*)directory[i].filename, path + 1) == 0) {
            file_entry = &directory[i];
            break;
        }
    }

    if (!file_entry) {
        return -ENOENT;  // File does not exist
    }

    // Load the FAT
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }

    if (read(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Handle shrinking the file
    if (size < file_entry->file_size) {
        uint16_t current_block = file_entry->start_block;
        off_t file_offset = 0;
        off_t bytes_to_free = file_entry->file_size - size;

        // Traverse the FAT chain to find which blocks need to be freed
        while (current_block != 0xFFFF && bytes_to_free > 0) {
            size_t block_size = BLOCK_SIZE;
            if (file_offset + block_size <= size) {
                file_offset += block_size;
                current_block = fat_table[current_block];
            }
            else {
                // We are at the block to truncate, so free the remaining blocks in the chain
                if (lseek(img_fd, current_block * BLOCK_SIZE, SEEK_SET) < 0) {
                    return -EIO;
                }

                // Mark the blocks after the truncation point as free in the FAT
                while (current_block != 0xFFFF) {
                    uint16_t next_block = fat_table[current_block];
                    fat_table[current_block] = 0;  // Free this block
                    current_block = next_block;
                }

                break;
            }
        }

        // Update the file size in the directory entry
        file_entry->file_size = size;
    }
    // Handle extending the file
    else if (size > file_entry->file_size) {
        uint16_t current_block = file_entry->start_block;
        off_t file_offset = file_entry->file_size;
        off_t bytes_to_allocate = size - file_entry->file_size;

        // Traverse the FAT chain to find the last block
        while (current_block != 0xFFFF) {
            current_block = fat_table[current_block];
        }

        // Allocate new blocks as needed
        while (bytes_to_allocate > 0) {
            uint16_t new_block = 0;
            // Find a free block in the FAT
            for (uint16_t i = 1; i < FAT_BLOCK_SIZE; ++i) {
                if (fat_table[i] == 0) {
                    fat_table[i] = 0xFFFF;  // Mark this block as used
                    new_block = i;
                    break;
                }
            }

            if (new_block == 0) {
                return -ENOSPC;  // No space left
            }

            // Link the new block to the FAT
            if (current_block != 0xFFFF) {
                fat_table[current_block] = new_block;
            }
            else {
                file_entry->start_block = new_block;  // First block in the chain
            }

            // Move to the next block
            current_block = new_block;
            bytes_to_allocate -= BLOCK_SIZE;
        }

        // Update the file size in the directory entry
        file_entry->file_size = size;
    }

    // Write the updated FAT table back to the image
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (write(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Write the updated directory back to the image
    if (lseek(img_fd, superblock.directory_start * BLOCK_SIZE, SEEK_SET) < 0) {
        return -EIO;
    }
    if (write(img_fd, directory, sizeof(directory)) != sizeof(directory)) {
        return -EIO;
    }

    return 0;
}
int memefs_unlink(const char* path) {
    // Sanity check
    if (img_fd < 0) {
        return -EBADF;
    }
    if (load_directory() < 0) {
        return -EIO;
    }

    const char* filename = path[0] == '/' ? path + 1 : path; // Remove leading '/'

    // Find the file in the directory
    int dir_index = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; ++i) {
        if (directory[i].filename[0] != 0x00 &&
            strncmp((const char*)directory[i].filename, filename, MAX_FILENAME_LEN) == 0) {
            dir_index = i;
            break;
        }
    }
    if (dir_index == -1) {
        return -ENOENT;
    }

    // Load FAT
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0 ||
        read(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Free all blocks in FAT
    uint16_t block = directory[dir_index].start_block;
    while (block != 0xFFFF && block != 0x0000) {
        uint16_t next_block = fat_table[block];
        fat_table[block] = 0x0000;
        block = next_block;
    }

    // Mark directory entry as unused
    memset(&directory[dir_index], 0, sizeof(memefs_dirent_t));
    directory[dir_index].filename[0] = 0x00; // mark unused

    // Write back updated FAT
    if (lseek(img_fd, superblock.main_fat * BLOCK_SIZE, SEEK_SET) < 0 ||
        write(img_fd, fat_table, sizeof(fat_table)) != sizeof(fat_table)) {
        return -EIO;
    }

    // Write back updated directory
    if (lseek(img_fd, superblock.directory_start * BLOCK_SIZE, SEEK_SET) < 0 ||
        write(img_fd, directory, sizeof(directory)) != sizeof(directory)) {
        return -EIO;
    }

    return 0;
}

static const struct fuse_operations memefs_oper = {
        .getattr = memefs_getattr,
        .readdir = memefs_readdir,
        .open = memefs_open,
        .read = memefs_read,
        .create = memefs_create,
        .write = memefs_write,
        .truncate = memefs_truncate,
        .unlink = memefs_unlink
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filesystem image> <mount point>\n", argv[0]);
        return 1;
    }

    // Open filesystem image
    img_fd = open(argv[1], O_RDWR);
    if (img_fd < 0) {
        perror("Failed to open filesystem image");
        return 1;
    }

    // HINT: Define helper functions: load_superblock and load_directory
    if (load_superblock() < 0 || load_directory() < 0) {
        //if (load_superblock() < 0) {
        fprintf(stderr, "Failed to load superblock or directory\n");
        //fprintf(stderr, "Failed to load superblock\n");
        close(img_fd);
        return 1;
    }

    return fuse_main(argc - 1, argv + 1, &memefs_oper, NULL);
}