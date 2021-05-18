#define INCLUDE_C_FILES

#ifdef INCLUDE_C_FILES
#include "../fs.c"
#include "../disk.c"
#else
#include "../fs.h"
// #include "../disk.h"
#endif

#define LONG_STR_LENGTH 5000

#include <stdio.h>
#include <assert.h>

int main() {
    printf("Attempting to create a new FS...\n");
    assert(make_fs("myVFS") == 0);
    printf("\tCreate a new FS succeed.\n\n");

    printf("Unmount a non-mounted VFS...\n");
    assert(umount_fs("myVFS") == -1);
    printf("\tUnmounting non-mounted VFS succeed to fail.\n\n");

    printf("Unmounting non-VFS file...\n");
    FILE *file = fopen("fakeVFS", "w");
    fputs("101000101010101010010101101001010001001101101", file);
    fclose(file);
    int ret = umount_fs("fakeVFS");
    remove("fakeVFS");
    assert(ret == -1);
    printf("\tUnmounting non-VFS file succeed to fail.\n\n");

    printf("Mounting VFS...\n");
    assert(mount_fs("myVFS") == 0);
    printf("\tMount VFS succeed.\n\n");

    printf("Testing files...\n");
    assert(fs_create("file1") == 0);

    printf("\tCreate a file with a file name that already exists: ");
    assert(fs_create("file1") == -1);
    printf("failed.\n");

    assert(fs_create("file2") == 0);

    printf("\tOpen a file twice...\n");
    printf("\t\tOpening file \"file1\"\n");
    int fd1 = fs_open("file1");
    assert(fd1 != -1);
    printf("\t\tOpening \"file1\" again\n");
    int fd2 = fs_open("file1");
    assert(fd2 != -1);
    printf("\tsuccess.\n");

    int fd3 = fs_open("file2");
    assert(fd3 != -1);
    printf("\tDelete an unclosed file: ");
    assert(fs_delete("file2") == -1);
    printf("failed\n");

    printf("\tCreate a file exceeding the maximum number of file descriptors: ");
    for (int i = 0; i < 29; ++i) {
        assert(fs_open("file1") != -1);
    }
    assert(fs_open("file1") == -1);
    printf("failed.\n");

    assert(fs_close(fd3) == 0);
    assert(fs_delete("file2") == 0);
    printf("\tDelete a file twice: ");
    assert(fs_delete("file2") == -1);
    printf("failed.\n");

    printf("File I/O...\n");
    printf("\tWrite \"hello, world!\" to \"file1\"\n");
    char input[] = "Hello, world!";
    int byte_wrote = fs_write(fd1, input, strlen(input));
    assert(byte_wrote ==  strlen(input));

    assert(fs_lseek(fd1, 4) == 0);

    char *output = (char*)malloc(2*BLOCK_SIZE);
    printf("\tRead from \"file1\"\n");
    int byte_read = fs_read(fd1, output, 10);
    assert(strcmp(output, "o, world!") == 0);
    printf("\tInput and output matched.\n");

    printf("\tclose fd1, read from fd2.\n");
    fs_close(fd1);
    assert(fs_lseek(fd2, 0) == 0);
    fs_read(fd2, output, strlen(input));
    assert(strcmp(input, output) == 0);
    printf("\tInput and output matched.\n\n");

    memset(output, 0, 2*BLOCK_SIZE);
    file = fopen("txt", "r");
    char long_str[LONG_STR_LENGTH];
    fgets(long_str, strlen(long_str), file);
    fs_write(fd2, long_str, strlen(long_str));
    fs_lseek(fd2, 0);
    fs_read(fd2, output, strlen(long_str));
    assert(strcmp(long_str, output) == 0);

    printf("List all files...\n");
    printf("-----------------\n");
    for (int i = 0; i < 8; ++i) {
        char name[6] = "nameX";
        name[4] = '0'+i;
        fs_create(name);
    }
    char **all_files;
    fs_listfiles(&all_files);
    for (int i = 0; i < 64; ++i) {
        if (all_files[i] != NULL) {
            printf("%s \n", all_files[i]);
        } else {
            break;
        }
    }
    printf("-----------------\n");

    return 0;
}