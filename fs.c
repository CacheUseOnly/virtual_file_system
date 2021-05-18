#include "fs.h"

uint8_t used_block_bitmap[DISK_BLOCKS/byte]; 
file_name_inode_map directory_entry[MAX_FILE_NUM];
inode inode_metadata[MAX_FILE_NUM];
super_block *sb;
fd file_descriptors[MAX_FD_NUM];
char curr_VFS[200];

void bitmap_set(uint8_t *bitmap, uint16_t index) {
    uint16_t element = index / byte;
    uint8_t offset = index % byte;

    bitmap[element] |= (128 >> offset);
}

void bitmap_clear(uint8_t *bitmap, uint16_t index) {
    uint16_t element = index / byte;
    uint8_t offset = index % byte;

    bitmap[element] &= (~(128 >> offset));
}

uint16_t get_first_free_bit(uint8_t *bitmap) {
    for (uint16_t i = 0; i < (DISK_BLOCKS/byte); ++i) {
        uint8_t test = 128;
        for (uint8_t j = 0; j < byte; ++j) {
            test = ~(test >> j);
            if ((bitmap[i] | test) == test) {
                return (i*8 + j);
            }
        }
    }

    return 0;
}

int make_fs(const char *disk_name) {
    TRACE_LOG(make disk, make_disk, disk_name)
    TRACE_LOG(open disk, open_disk, disk_name)

    void *buf = malloc(BLOCK_SIZE);
    memset(buf, 0, BLOCK_SIZE);

    // write super block
    sb = (super_block*) malloc(sizeof(super_block));
    memset(sb, 0, sizeof *sb);
    sb->magic_num = MAGIC_NUM;
    sb->used_block_bitmap_count = DISK_BLOCKS/(BLOCK_SIZE*byte) + 1;   // should equal to 1 in this case
    sb->used_block_bitmap_offset = sizeof(super_block)/BLOCK_SIZE + 1;
    sb->inode_metadata_blocks = MAX_FILE_NUM * sizeof(inode) / BLOCK_SIZE + 1;
    sb->inode_metadata_offset = sb->used_block_bitmap_offset + sb->used_block_bitmap_count;
    sb->dir_entry_blocks = MAX_FILE_NUM * sizeof(file_name_inode_map) / BLOCK_SIZE + 1;
    sb->dir_entry_offset = sb->inode_metadata_offset + sb->inode_metadata_blocks + sb->dir_entry_blocks - 1;
    memcpy(buf, sb, sizeof(super_block));
    TRACE_LOG(write super block, block_write, 0, buf)

    // write bit map
    // reserve for metadata
    for (int i = 0; i < sb->inode_metadata_offset + sb->inode_metadata_blocks; ++i) {
        bitmap_set(used_block_bitmap, i);
    }
    memcpy(buf, used_block_bitmap, DISK_BLOCKS/byte);
    TRACE_LOG(write bitmap, block_write, sb->used_block_bitmap_offset, buf)

    // write inode metadata
    memcpy(buf, inode_metadata, MAX_FILE_NUM * sizeof(inode));
    TRACE_LOG(write inode metadata, block_write, sb->inode_metadata_offset, buf) 

    // write dir_entry
    memcpy(buf, directory_entry, sizeof(file_name_inode_map)*MAX_FILE_NUM);
    TRACE_LOG(write dentry, block_write, sb->dir_entry_offset, buf)

    free(buf);  
    free(sb);
    TRACE_LOG(close disk, close_disk)
    return 0;
}

int mount_fs(const char *disk_name) {
    TRACE_LOG(open disk, open_disk, disk_name)

    void *buf = malloc(BLOCK_SIZE);

    sb = (super_block*) malloc(sizeof(super_block));
    memset(sb, 0, sizeof(super_block));
    TRACE_LOG(read super block, block_read, 0, buf) 
    memcpy(sb, buf, sizeof(super_block));
    if (sb->magic_num != MAGIC_NUM || sb->dir_entry_offset == 0 || sb->inode_metadata_offset == 0 || sb->used_block_bitmap_offset == 0) {
        fprintf(stderr, "Super block corrupted.\n");
        close_disk();
        return -1;
    }

    TRACE_LOG(read used bitmap, block_read, sb->used_block_bitmap_offset, buf)
    memcpy(used_block_bitmap, buf, DISK_BLOCKS/byte);
    TRACE_LOG(read inode metadata, block_read, sb->inode_metadata_offset, buf)
    memcpy(inode_metadata, buf, MAX_FILE_NUM * sizeof(inode));
    TRACE_LOG(read dentry, block_read, sb->dir_entry_offset, buf)
    memcpy(directory_entry, buf, sizeof(file_name_inode_map)*MAX_FILE_NUM);

    strcpy(curr_VFS, disk_name);

    free(buf); // free(): invalid pointer
    free(sb);
    TRACE_LOG(close_disk, close_disk)
    return 0;
}

int umount_fs(const char *disk_name) {
    TRACE_LOG(open disk, open_disk, disk_name)

    void *buf = malloc(BLOCK_SIZE);

    // check if current VFS is mounted
    if (strcmp(curr_VFS, disk_name) != 0) {
        fprintf(stderr, "Current VFS is not mounted.\n");
        TRACE_LOG(close disk, close_disk);
        return -1;
    }

    // check if it's a real virual disk image
    sb = (super_block*) malloc(sizeof(super_block));
    TRACE_LOG(read super block, block_read, 0, buf) 
    memcpy(sb, buf, BLOCK_SIZE);
    if (sb->magic_num != MAGIC_NUM || sb->dir_entry_offset == 0 || sb->inode_metadata_offset == 0 || sb->used_block_bitmap_offset == 0) {
        fprintf(stderr, "It's not a virtual disk image\n");
        return -1;
    }

    memcpy(buf, used_block_bitmap, DISK_BLOCKS/byte);
    TRACE_LOG(write used bitmap, block_write, sb->used_block_bitmap_offset, buf)
    memcpy(buf, inode_metadata, MAX_FILE_NUM * sizeof(inode));
    TRACE_LOG(write inode metadata, block_write, sb->inode_metadata_offset, buf)
    memcpy(buf, directory_entry, MAX_FILE_NUM * sizeof(file_name_inode_map));
    TRACE_LOG(write dentry, block_write, sb->dir_entry_offset, buf)

    curr_VFS[0] = '\0';

    TRACE_LOG(close disk, close_disk)
    return 0;
}

int fs_open(const char* name) {
    open_disk(curr_VFS);
    int8_t index = -1;
    for (int i = 0; i < MAX_FD_NUM; ++i) {
        if (file_descriptors[i].is_used == 0) {
            index = i;
            file_descriptors[i].is_used = 1;
            break;
        }
    }
    if (index == -1) {
        fprintf(stderr, "Maximum number of simultaneously opened file reached.\n");
        close_disk();
        return -1;
    }

    char found = 0;
    for (int i = 0; i < MAX_FD_NUM; ++i) {
        if (strcmp(name, directory_entry[i].file_name) == 0) {
            file_descriptors[index].inode_number = directory_entry[i].inode_offset;
            file_descriptors[index].offset = 0;
            strcpy(file_descriptors[index].name, name);
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "Not found.\n");
        file_descriptors[index].is_used = 0;
        return -1;
    }

    close_disk();
    return index;
}

int fs_close(int fd) {
    if (fd < 0 || fd > MAX_FD_NUM || file_descriptors[fd].is_used == 0) {
        fprintf(stderr, "Invalid fd.\n");
        return -1;
    }

    file_descriptors[fd].is_used = 0;
    file_descriptors[fd].inode_number = 0;
    file_descriptors[fd].offset = 0;
    memset(file_descriptors[fd].name, 0, strlen(file_descriptors[fd].name));
    return 0;
}

int fs_create(const char* name) {
    open_disk(curr_VFS);
    if (strlen(name) > MAX_FILENAME_LENGTH) {
        fprintf(stderr, "File name too long.\n");
        close_disk();
        return -1;
    }

    char found = 0;
    uint8_t dentry_index = 0;
    for (int i = 0; i < MAX_FILE_NUM; ++i) {
        if (strcmp(directory_entry[i].file_name, name) == 0) {
            fprintf(stderr, "File with the name already existed.\n");
            close_disk();
            return -1;
        }
        if (directory_entry[i].is_used == NOT_USED) {
            dentry_index = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "Maximum number of stored file reached.\n");
        close_disk();
        return -1;
    }

    uint8_t inode_index = 0;
    found = 0;
    for (int i = 0; i < MAX_FILE_NUM; ++i) {
        if(inode_metadata[i].file_type == NOT_USED) {
            inode_index = i;
            inode_metadata[i].file_type = FILE_TYPE;
            inode_metadata[i].file_size = 0;
            inode_metadata[i].single_indirect = 0;
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "Maximum number of stored file reached.\n");
        close_disk();
        return -1;
    }
    strcpy(directory_entry[dentry_index].file_name, name);
    directory_entry[dentry_index].inode_offset = inode_index;
    directory_entry[dentry_index].is_used = 1;

    close_disk();
    return 0;
}

int fs_delete(const char* name) {
    open_disk(curr_VFS);
    char found = 0;
    uint8_t dir_index = 0;
    for (int i = 0; i < MAX_FILE_NUM; ++i) {
        if (i < MAX_FD_NUM && strcmp(file_descriptors[i].name, name) == 0) {
            fprintf(stderr, "The file is in use.\n");
            close_disk();
            return -1;
        }
        if (strcmp(directory_entry[i].file_name, name) == 0) {
            found = 1;
            dir_index = i;
        }
    }
    if (!found) {
        fprintf(stderr, "Cannot find file with given name.\n");
        close_disk();
        return -1;
    }

    // clear direct offset
    for (int i = 0; inode_metadata[directory_entry[dir_index].inode_offset].direct_offset[i] != 0; ++i) {
        bitmap_clear(used_block_bitmap, inode_metadata[directory_entry[dir_index].inode_offset].direct_offset[i]);
        inode_metadata[directory_entry[dir_index].inode_offset].direct_offset[i] = 0;
    }
    // clear single indirect offset
    // TODO
    char *single_indir = (char*)malloc(BLOCK_SIZE);
    TRACE_LOG(read single indirect block, block_read, 
        inode_metadata[directory_entry[dir_index].inode_offset].single_indirect, single_indir)
    for (int i = 0; single_indir[i] != 0; ++i) {
        bitmap_clear(used_block_bitmap, single_indir[i]);
    }
    char *zeros = (char*)calloc(BLOCK_SIZE/sizeof(char), sizeof(char));
    TRACE_LOG(clear single indirect block, block_write, 
        inode_metadata[directory_entry[dir_index].inode_offset].single_indirect, zeros)
    free(zeros);
    inode_metadata[directory_entry[dir_index].inode_offset].file_size = 0;
    inode_metadata[directory_entry[dir_index].inode_offset].file_type = NOT_USED;

    memset(directory_entry[dir_index].file_name, 0, strlen(directory_entry[dir_index].file_name));
    directory_entry[dir_index].inode_offset = 0;
    directory_entry[dir_index].is_used = NOT_USED;

    close_disk();
    return 0;
}

int fs_read(int fd, void *buf, size_t nbyte) {
    open_disk(curr_VFS);
    if (fd < 0 || fd > MAX_FD_NUM\
    || file_descriptors[fd].is_used == NOT_USED
    || inode_metadata[file_descriptors[fd].inode_number].file_type == NOT_USED) {
        fprintf(stderr, "Invalid fd.\n");
        close_disk();
        return -1;
    }

    int bytes_read = 0;
    int entry_index, offset, block_num;
    char mode = 0;      // 0 for direct, 1 for single indirect
    uint16_t *single_indirect = NULL;
    if (inode_metadata[file_descriptors[fd].inode_number].single_indirect != 0) {
        single_indirect = (uint16_t*)malloc(BLOCK_SIZE);
        TRACE_LOG(read single indirect block, block_read, 
            inode_metadata[file_descriptors[fd].inode_number].single_indirect, single_indirect)
    }
    if (file_descriptors[fd].offset <= ENTRY_NUM * BLOCK_SIZE) {
        // Use direct offset
        entry_index = file_descriptors[fd].offset / BLOCK_SIZE;
        offset = file_descriptors[fd].offset % BLOCK_SIZE;
        block_num = inode_metadata[file_descriptors[fd].inode_number].direct_offset[entry_index];
        mode = 0;
    } else {
        // Use single indirect offset
        if (single_indirect == NULL) {
            fprintf(stderr, "Invalid offset.\n");
            close_disk();
            return -1;
        }
        entry_index = file_descriptors[fd].offset / BLOCK_SIZE - ENTRY_NUM;
        offset = file_descriptors[fd].offset%BLOCK_SIZE;
        block_num = single_indirect[entry_index];
        mode = 1;
    }

    char *buffer = malloc(BLOCK_SIZE);
    while (1) {
        TRACE_LOG(read block into buffer, block_read, block_num, buffer)
        for (int i = offset; (bytes_read < nbyte) && (i < BLOCK_SIZE); ++bytes_read, ++i) {
            *((char*)(buf)+ bytes_read) = buffer[i]; 
        }

        // more to be read
        if (nbyte != bytes_read) {
            // if currently using direct offsets
            if (mode == 0) {
                // if more at direct offsets
                if (entry_index < ENTRY_NUM) {
                    block_num = inode_metadata[file_descriptors[fd].inode_number].direct_offset[++entry_index];
                    if (block_num == 0) break;      // EOF reached
                // if more at single indirect
                } else {
                    if (inode_metadata[file_descriptors[fd].inode_number].single_indirect == 0) {
                        break;                      // EOF reached
                    }
                    entry_index = 0;
                    block_num = single_indirect[entry_index];
                    mode = 1;
                }
            // if currently in single indirect
            } else if (mode == 1) {
                // if more at single indirect
                if (entry_index < BLOCK_SIZE/sizeof(uint16_t)) {
                    block_num = single_indirect[++entry_index];
                // EOF reached
                } else {
                    break;  
                }
            }
            offset = 0;         // offset should set to zero after first iteration
        // nbyte bytes have been read
        } else {
            break;
        }
    }

    close_disk();
    return bytes_read;
}

int fs_write(int fd, const void *buf, size_t nbyte) {
    open_disk(curr_VFS);
    if (fd < 0 || fd > MAX_FD_NUM\
    || file_descriptors[fd].is_used == NOT_USED
    || inode_metadata[file_descriptors[fd].inode_number].file_type == NOT_USED) {
        fprintf(stderr, "Invalid fd.\n");
        close_disk();
        return -1;
    }

    int bytes_wrote = 0;

    // if it's the first write
    if (inode_metadata[file_descriptors[fd].inode_number].direct_offset[0] == 0) {
        inode_metadata[file_descriptors[fd].inode_number].direct_offset[0] = get_first_free_bit(used_block_bitmap);
        if (inode_metadata[file_descriptors[fd].inode_number].direct_offset[0] == 0) {
            fprintf(stderr, "No more free space.\n");
            close_disk();
            return bytes_wrote;
        }
    }

    int entry_index, offset, block_num;
    char mode = 0;      // 0 for direct, 1 for single indirect
    uint16_t *single_indirect = NULL;
    if (inode_metadata[file_descriptors[fd].inode_number].single_indirect != 0) {
        single_indirect = (uint16_t*)malloc(BLOCK_SIZE);
        TRACE_LOG(read single indirect block, block_read, 
            inode_metadata[file_descriptors[fd].inode_number].single_indirect, single_indirect)
    }
    if (file_descriptors[fd].offset <= ENTRY_NUM * BLOCK_SIZE) {
        // Use direct offset
        entry_index = file_descriptors[fd].offset / BLOCK_SIZE;
        offset = file_descriptors[fd].offset % BLOCK_SIZE;
        block_num = inode_metadata[file_descriptors[fd].inode_number].direct_offset[entry_index];
        mode = 0;
    } else {
        // Use single indirect offset
        if (single_indirect == NULL) {
            fprintf(stderr, "Invalid offset.\n");
            close_disk();
            return -1;
        }
        entry_index = file_descriptors[fd].offset / BLOCK_SIZE - ENTRY_NUM;
        offset = file_descriptors[fd].offset%BLOCK_SIZE;
        block_num = single_indirect[entry_index];
        mode = 1;
    }

    while (1) {
        char *temp = (char*)malloc(BLOCK_SIZE);
        TRACE_LOG(read block to temp, block_read, block_num, temp)
        for (int i = 0; (bytes_wrote != nbyte) && (i + offset < BLOCK_SIZE); ++bytes_wrote, ++i) {
            *(temp + offset + i) = *((char*)(buf) + bytes_wrote);
        }
        TRACE_LOG(update the block, block_write, block_num, temp)

        // if there is more to be wrote
        if (nbyte != bytes_wrote) {
            // if currently using direct block
            if (mode == 0) {
                // direct block storage is still available
                if (entry_index < ENTRY_NUM) {
                    block_num = get_first_free_bit(used_block_bitmap);
                    bitmap_set(used_block_bitmap, block_num);
                    inode_metadata[file_descriptors[fd].inode_number].direct_offset[++entry_index] = block_num;
                // switch to indirect offset
                } else {
                    block_num = get_first_free_bit(used_block_bitmap);
                    bitmap_set(used_block_bitmap, block_num);
                    single_indirect = (uint16_t*)calloc(BLOCK_SIZE/sizeof(uint16_t), sizeof(uint16_t));
                    single_indirect[0] = block_num;
                    inode_metadata[file_descriptors[fd].inode_number].single_indirect = get_first_free_bit(used_block_bitmap);
                    bitmap_set(used_block_bitmap, inode_metadata[file_descriptors[fd].inode_number].single_indirect);
                    TRACE_LOG(allocate single indirect block, block_write, 
                        inode_metadata[file_descriptors[fd].inode_number].single_indirect, single_indirect);
                }
            // if currently using indirect offset
            } else if (mode == 1) {
                // available space in single indirect
                if (entry_index < (BLOCK_SIZE/sizeof(uint16_t))) {
                    block_num = get_first_free_bit(used_block_bitmap);
                    bitmap_set(used_block_bitmap, block_num);
                    single_indirect[++entry_index] = block_num;
                    TRACE_LOG(update single indirect block, block_write, 
                        inode_metadata[file_descriptors[fd].inode_number].single_indirect, single_indirect);
                // reached maximum file size
                } else {
                    break;
                }
            }
            offset = 1;     // discard offset after first iteration
        // wrote all bytes
        } else {
            break;
        }
    }

    inode_metadata[file_descriptors[fd].inode_number].file_size += bytes_wrote;
    file_descriptors[fd].offset += bytes_wrote;

    close_disk();
    return bytes_wrote;
}

int fs_get_filesize(int fd) {
    open_disk(curr_VFS);
    if (fd < 0 || fd > MAX_FD_NUM\
    || file_descriptors[fd].is_used == NOT_USED
    || inode_metadata[file_descriptors[fd].inode_number].file_type == NOT_USED) {
        fprintf(stderr, "Invalid fd.\n");
        close_disk();
        return -1;
    }

    close_disk();
    return inode_metadata[file_descriptors[fd].inode_number].file_size; 
}

int fs_listfiles(char ***files) {
    open_disk(curr_VFS);
    int i = 0;
    *files = (char**)malloc(MAX_FILE_NUM*MAX_FILENAME_LENGTH);
    for (; i < MAX_FILE_NUM; ++i) {
        if (directory_entry[i].is_used == 1) {
            (*files)[i] = (char*)malloc(MAX_FILENAME_LENGTH);
            TRACE_LOG(concat to the list, strcpy, (*files)[i], directory_entry[i].file_name)
        }
    }
    files[i] = NULL;

    close_disk();
    return 0;
}

int fs_lseek(int fildes, off_t offset) {
    open_disk(curr_VFS);
    if (fildes < 0 || fildes > MAX_FD_NUM\
    || file_descriptors[fildes].is_used == NOT_USED
    || inode_metadata[file_descriptors[fildes].inode_number].file_type == NOT_USED) {
        fprintf(stderr, "Invalid fd.\n");
        close_disk();
        return -1;
    }
    if (offset > inode_metadata[file_descriptors[fildes].inode_number].file_size) {
        fprintf(stderr, "Exceeding file size.\n");
        close_disk();
        return -1;
    }

    file_descriptors[fildes].offset = offset;
    close_disk();
    return 0;
}

int fs_truncate(int fd, off_t length) {
    open_disk(curr_VFS);
    if (fd < 0 || fd > MAX_FD_NUM\
    || file_descriptors[fd].is_used == NOT_USED
    || inode_metadata[file_descriptors[fd].inode_number].file_type == NOT_USED) {
        fprintf(stderr, "Invalid fd.\n");
        close_disk();
        return -1;
    }
    if (length > inode_metadata[file_descriptors[fd].inode_number].file_size) {
        fprintf(stderr, "Exceeding file size.\n");
        close_disk();
        return -1;
    }

    int bytes_freed = 0;

    int entry_index, offset, block_num;
    char mode = 0;      // 0 for direct, 1 for single indirect
    uint16_t *single_indirect = NULL;
    if (inode_metadata[file_descriptors[fd].inode_number].single_indirect != 0) {
        single_indirect = (uint16_t*)malloc(BLOCK_SIZE);
        TRACE_LOG(read single indirect block, block_read, 
            inode_metadata[file_descriptors[fd].inode_number].single_indirect, single_indirect)
    }
    // Use direct offset
    if (length <= ENTRY_NUM * BLOCK_SIZE) {
        entry_index = length / BLOCK_SIZE;
        offset = length % BLOCK_SIZE;
        block_num = inode_metadata[file_descriptors[fd].inode_number].direct_offset[entry_index];
        mode = 0;
    // Use single indirect offset
    } else {
        if (single_indirect == NULL) {
            fprintf(stderr, "Invalid offset.\n");
            close_disk();
            return -1;
        }
        entry_index = length / BLOCK_SIZE - ENTRY_NUM;
        offset = length %BLOCK_SIZE;
        block_num = single_indirect[entry_index];
        mode = 1;
    }

    while (1) {
        char *temp = (char*)malloc(BLOCK_SIZE);
        TRACE_LOG(read block to temp, block_read, block_num, temp)
        for (int i = 0; (offset + i) < BLOCK_SIZE; ++bytes_freed, ++i) {
            *(temp + offset + i) = 0;
        }
        TRACE_LOG(update the block, block_write, block_num, temp)
        if (offset == 0) {
            bitmap_clear(used_block_bitmap, block_num);
        }

        // more to be freed
        if (bytes_freed + length < inode_metadata[file_descriptors[fd].inode_number].file_size) {
            // if currently using direct offsets
            if (mode == 0) {
                // if more at direct offsets
                if (entry_index < ENTRY_NUM) {
                    block_num = inode_metadata[file_descriptors[fd].inode_number].direct_offset[++entry_index];
                // if more at single indirect
                } else {
                    entry_index = 0;
                    block_num = single_indirect[entry_index];
                    mode = 1;
                }
            // if currently in single indirect
            } else if (mode == 1) {
                // if more at single indirect
                if (entry_index < BLOCK_SIZE/sizeof(uint16_t)) {
                    block_num = single_indirect[++entry_index];
                // EOF reached
                } else {
                    break;  
                }
            }
            offset = 0;         // offset should set to zero after first iteration
        // nbyte bytes have been read
        } else {
            break;
        }
    }
    inode_metadata[file_descriptors[fd].inode_number].file_size -= bytes_freed;
    file_descriptors[fd].offset = ((file_descriptors[fd].offset < inode_metadata[file_descriptors[fd].inode_number].file_size)? 
        file_descriptors[fd].offset : inode_metadata[file_descriptors[fd].inode_number].file_size);

    close_disk();
    return 0;
}