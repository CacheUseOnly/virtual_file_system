#ifndef INCLUDE_FS_H
#define INCLUDE_FS_H
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "disk.h"

#define byte 8
#define ENTRY_NUM 16
#define MAX_FD_NUM 32
#define MAX_FILE_NUM 64
#define MAX_FILENAME_LENGTH 16
#define MAGIC_NUM 42

#define TRACE_LOG(debug_str, function, ...) \
    if (function(__VA_ARGS__) == -1) {\
        fprintf(stderr, "Cannot " #debug_str ".\n");\
        return -1;\
    }

int make_fs(const char *disk_name);
int mount_fs(const char *disk_name);
int umount_fs(const char *disk_name);
int fs_open(const char *name);
int fs_close(int fildes);
int fs_create(const char *name);
int fs_delete(const char *name);
int fs_read(int fildes, void *buf, size_t nbyte);
int fs_write(int fildes, const void *buf, size_t nbyte);
int fs_get_filesize(int fildes);
int fs_listfiles(char ***files);
int fs_lseek(int fildes, off_t offset);
int fs_truncate(int fildes, off_t length);

void bitmap_set(uint8_t *bitmap, uint16_t index);
void bitmap_clear(uint8_t *bitmap, uint16_t index);
uint16_t get_first_free_bit(uint8_t *bitmap);

typedef struct super_block_t { 
    uint8_t magic_num;                  // virtual file image identification
    uint16_t used_block_bitmap_count;
    uint16_t used_block_bitmap_offset;
    uint16_t inode_metadata_blocks;
    uint16_t inode_metadata_offset;
    uint16_t dir_entry_blocks;
    uint16_t dir_entry_offset;
} super_block;

typedef struct indirect_block_t {
    uint16_t offset[BLOCK_SIZE/sizeof(uint16_t)];
} indirect_block;

enum e_file_type {
    NOT_USED,
    FILE_TYPE,
    DIR_TYPE
};

typedef struct inode_t {
    uint8_t file_type;
    uint16_t direct_offset[ENTRY_NUM];
    uint16_t single_indirect;
    unsigned long file_size;
} inode;

typedef struct file_name_inode_map_t {
    char file_name[MAX_FILENAME_LENGTH];
    uint8_t inode_offset;
    char is_used;
} file_name_inode_map;

typedef struct dir_entry_t {
    uint8_t isused;
    uint16_t inode_number;
    char name[MAX_FILENAME_LENGTH];
} dir_entry;

typedef struct file_descriptor {
    char is_used;
    uint8_t inode_number;
    int offset;
    char name[MAX_FILENAME_LENGTH];
} fd;

#endif /* INCLUDE_FS_H */
