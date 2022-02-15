
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FAT_EOC 0xFFFF
#define BLOCK_SIZE 4096
#define SIG "ECS150FS"

struct SuperblockC{
    uint8_t Signature[8]; //could use char here 8 * 8 = 64 same as uint64
    uint16_t NumBlocks;
    uint16_t IndexRD;  // Root Drirectory block index
    uint16_t IndexDataB; //Index of Data Blocks
    uint16_t NumDataB;
    uint8_t NumFAT;
    uint8_t Padding[BLOCK_SIZE - 17]; //BLOCK_SIZE - (8 + 2 X 4 + 1 )
} __attribute__((packed));

struct SuperblockC *SuperB = NULL;  //later easier for check if the sys is mount or not
uint16_t *FATt; //FATtable

struct RootDir{
    uint8_t Filename[16]; //16 * 8 = 128 16byts
    uint32_t SizeofF; //size of File 4 byts
    uint16_t IndexofF; //indexof the first data block 2 byts
    uint8_t Padding[10];
} __attribute__((packed));

struct RootDirD{ //Dir arry of store all roots
    struct RootDir Dirclass[128];
} __attribute__((packed));

struct RootDirD *RootB;



int fs_mount(const char *diskname)
{

    if (block_disk_open(diskname) == -1){
        return -1;
    }
    //init super
    SuperB = calloc(1, sizeof(struct SuperblockC));
    if (SuperB == NULL){
        return -1;
    }
    //read super
    if (block_read(0, SuperB) == -1){ //check if fails or not
        return -1;
    }
    if (memcmp((char *)"ECS150FS", SuperB->Signature, strlen("ECS150FS")) != 0){
        free(SuperB);
        return -1;
    }
    if (SuperB->NumBlocks != block_disk_count()){
        free(SuperB);
        return -1;
    }
    //read FAT
    FATt = calloc(BLOCK_SIZE, SuperB->NumFAT);
    for (int i = 0; i < SuperB->NumFAT; ++i){
        if (block_read(i + 1, i * BLOCK_SIZE + (void*)FATt) == -1){
            return -1;
        }
    }

    for (int i = 0;i < 8;i++) {
      uint8_t *cur_block = calloc(BLOCK_SIZE, 1);

      if (block_read(i, cur_block) == -1) {
	return -1;
      }

      free(cur_block);
      cur_block = NULL;
    }

    //read root dir
    RootB = calloc(1, sizeof(struct RootDirD));
    if(block_read(SuperB->IndexRD, RootB) == -1){
        return 0;
    }

    return 0;
}

int fs_umount(void)
{
  if (block_disk_count() == -1) {
    return -1;
  }

  //write all metadata out to disk
  //Root Dir
  if( block_write(SuperB->IndexRD, RootB) == -1){
    return -1;
  }

  //FAT
  for (int i = 0; i < SuperB->NumFAT; ++i){
    block_write(i + 1, i * BLOCK_SIZE + (char *)FATt);
  }

  //delete
  free(SuperB);
  free(FATt);
  free(RootB);

  //close
  if (block_disk_close() < 0){
    return -1;
  }
  return 0;
}


int fs_info(void)
{
    if (block_disk_count() == -1)
        return -1;
    int total_blk = 2 + SuperB->NumFAT + SuperB->NumDataB; // 1 is supper 1 is root dir

    printf("FS Info:\n");
    printf("total_blk_count=%d\n",total_blk);
    printf("fat_blk_count=%d\n",SuperB->NumFAT);
    printf("rdir_blk=%d\n", SuperB->IndexRD);
    printf("data_blk=%d\n", SuperB->IndexDataB);
    printf("data_blk_count=%d\n", SuperB->NumDataB);
    //get fat free block
    int fat_free = 0;
    for (int i = 0; i <SuperB->NumDataB; ++i){
        if(FATt[i] == 0){
            fat_free++;
        }
    }
    //get root dir free block
    int rdir_free = 0;
    for (int i = 0; i < FS_FILE_MAX_COUNT; ++i){ //FS_FILE_MAX_COUNT is max num of root dir
        if (RootB->Dirclass[i].Filename[0] == '\0'){
            rdir_free++;
        }
    }

    printf("fat_free_ratio=%d/%d\n",fat_free, SuperB->NumDataB);
    printf("rdir_free_ratio=%d/%d\n",rdir_free, FS_FILE_MAX_COUNT);

    return 0;
}
/**
 * fs_create - Create a new file
 * @filename: File name
 *
 * Create a new and empty file named @filename in the root directory of the
 * mounted file system. String @filename must be NULL-terminated and its total
 * length cannot exceed %FS_FILENAME_LEN characters (including the NULL
 * character).
 *
 * Return: -1 if @filename is invalid, if a file named @filename already exists,
 * or if string @filename is too long, or if the root directory already contains
 * %FS_FILE_MAX_COUNT files. 0 otherwise.
 */
int fs_create(const char *filename)
{
    /*THREE CHECKS*/
    //check too long
    if (strlen(filename) > FS_FILENAME_LEN){
        return -1;
    }
    //check exist
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
        if (strcmp((char *)RootB->Dirclass[i].Filename, filename) == 0){ //cast Filename to char
	  return -1;
        }
    }
    //check if root max (more than 128 file)
    int indx_count;
    for (indx_count = 0; indx_count < FS_FILE_MAX_COUNT; ++indx_count ){
        if (RootB->Dirclass[indx_count].Filename[0] == '\0'){
            break;
        }
    }
    if (indx_count >= 127){ //which means we went throught 128 times
        return -1;
    }
    /*finish checking*/

    //find first open entry
    int open;
    for (open = 0; open < FS_FILE_MAX_COUNT; ++open){
      if (RootB->Dirclass[open].Filename[0] == '\0'){
	strcpy((char *)RootB->Dirclass[open].Filename, filename); //specific
	RootB->Dirclass[open].SizeofF = 0;
	RootB->Dirclass[open].IndexofF = FAT_EOC; //start with this
	return 0;
      }
    }

    return -1; // Max File Capacity
}

int fat_delete(const int index){
    uint16_t current = RootB->Dirclass[index].IndexofF;
    int temp; //temp of index
    while(current != FAT_EOC){
        temp = FATt[current];//FAT table
        FATt[current] = 0;
        current = temp;
    }

    return 0;
}



int fs_delete(const char *filename)
{
    /*THREE CHECKS*/
    //check invalid
    if (filename == NULL || strlen(filename) > FS_FILENAME_LEN){
        return -1;
    }
    //check exist
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
        if (strcmp((char *)RootB->Dirclass[i].Filename, filename) == 0){ //cast Filename to char
            break;
        }
        if (i == FS_OPEN_MAX_COUNT - 1){
            return -1;
        }
    }
    /*finish checking*/

    //delect
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
        if(strcmp((char *)RootB->Dirclass[i].Filename, filename) == 0){
            //delete filename
            strcpy((char *)RootB->Dirclass[i].Filename, "");

            //delete info in fat
            fat_delete(i);
        }
        break;
    }
    return 0;

}
/**
 * fs_ls - List files on file system
 *
 * List information about the files located in the root directory.
 *
 * Return: -1 if no underlying virtual disk was opened. 0 otherwise.
 */
int fs_ls(void)
{
    if (block_disk_count() == -1){
        return -1;
    }

    printf("FS Ls:\n");
    for (size_t i = 0;i < 128;i++) {
      if (RootB->Dirclass[i].Filename[0] != 0) {
	printf("file: %s, size: %d, data_blk: %d\n",
	       RootB->Dirclass[i].Filename,
	       RootB->Dirclass[i].SizeofF,
	       RootB->Dirclass[i].IndexofF);
      }
    }
    return 0;
}

struct FileDescriptorElem {
  const char* FileName;
  size_t FileOffset;
};

struct FileDescriptorElem *FileDescriptor;

static int fd_alloc() {
  if (FileDescriptor == NULL) {
    FileDescriptor = calloc(32, sizeof(struct FileDescriptorElem));
    if (FileDescriptor == NULL) {
      return -1;
    }
  }
  return 0;
}

int fs_open(const char *filename)
{
  fd_alloc();

  if (filename == NULL) {
    return -1;
  }

  for (int i = 0;i < 32;i++) {
    if (FileDescriptor[i].FileName == NULL) {
      // Create the File
      FileDescriptor[i].FileName = filename;
      FileDescriptor[i].FileOffset = 0;

      return i;
    }
  }

  return 0;
}

int fs_close(int fd)
{
  fd_alloc();
  FileDescriptor[fd].FileName = NULL;
  FileDescriptor[fd].FileOffset = 0;
  return 0;
}

static int fs_root_dir_from_fd(int fd) {
  for (size_t i = 0;i < 128;i++) {
    if (strcmp(FileDescriptor[fd].FileName, (char*)RootB->Dirclass[i].Filename) == 0) {
      return i;
    }
  }
  return -1;
}

int fs_stat(int fd)
{
  fd_alloc();
  int root_dir_fs = fs_root_dir_from_fd(fd);
  if (root_dir_fs == -1) {
    return -1;
  } else {
    return RootB->Dirclass[root_dir_fs].SizeofF;
  }
}

int fs_lseek(int fd, size_t offset)
{
  fd_alloc();
  FileDescriptor[fd].FileOffset = offset;
  return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
  fd_alloc();

  uint8_t *cur_file = NULL;
  size_t cur_file_size = fs_stat(fd);

  cur_file = calloc(cur_file_size, 1);
  cur_file = realloc(cur_file, cur_file_size + BLOCK_SIZE); // NOTE: We write back as if this is an array of blocks

  if (cur_file == NULL) {
    return -1;
  } else {
    memset(cur_file + cur_file_size, 0, BLOCK_SIZE);
    const size_t write_max_size = FileDescriptor[fd].FileOffset + count;
    if (write_max_size > cur_file_size) {
      cur_file = realloc(cur_file, write_max_size);
      cur_file_size = write_max_size;
    }
    memcpy(cur_file + FileDescriptor[fd].FileOffset, buf, count);
  }

  size_t cur_file_write_size = 0;

  if (RootB->Dirclass[fs_root_dir_from_fd(fd)].IndexofF == FAT_EOC) {
    for (size_t i = 0;i < SuperB->NumFAT * (BLOCK_SIZE / sizeof(uint16_t));i++) {
      if (FATt[i] == 0) {
	RootB->Dirclass[fs_root_dir_from_fd(fd)].IndexofF = i;
	FATt[i] = FAT_EOC;
	break;
      }
    }
  }

  int root_dir_pos = fs_root_dir_from_fd(fd);
  uint16_t fat_start = RootB->Dirclass[root_dir_pos].IndexofF;

  while (cur_file_write_size < cur_file_size) {
    if (block_write(fat_start + SuperB->IndexDataB, cur_file + cur_file_write_size) == -1) {
      return -1;
    } else {
      cur_file_write_size += BLOCK_SIZE;
      if (FATt[fat_start] == FAT_EOC && cur_file_write_size < cur_file_size) {
	for (size_t i = 0;i < SuperB->NumFAT * (BLOCK_SIZE / sizeof(uint16_t));i++) {
	  if (FATt[i] == 0) {
	    FATt[fat_start] = i;
	    FATt[i] = FAT_EOC;
	    break;
	  }
	}
      }

      fat_start = FATt[fat_start];
    }
  }

  RootB->Dirclass[root_dir_pos].SizeofF = count;

  free(cur_file);
  cur_file = NULL;

  return count;
}

int fs_read(int fd, void *buf, size_t count)
{
  fd_alloc();
  memset(buf, 0, count);

  uint8_t *cur_block = calloc(BLOCK_SIZE, sizeof(uint8_t));
  uint8_t *cur_file = NULL;
  size_t cur_file_size = 0;

  int root_dir_pos = fs_root_dir_from_fd(fd);
  if (root_dir_pos == -1) {
    return -1;
  } else {
    int fat_start = RootB->Dirclass[root_dir_pos].IndexofF;

    do {
      if (block_read(fat_start + SuperB->IndexDataB, cur_block) == -1) {
	return -1;
      } else {
	cur_file = malloc(cur_file_size + BLOCK_SIZE);
	memcpy(cur_file + cur_file_size, cur_block, BLOCK_SIZE);
	cur_file_size += BLOCK_SIZE;

	fat_start = FATt[fat_start];
      }
    } while (fat_start != FAT_EOC);
  }

  const size_t read_end_pos = FileDescriptor[fd].FileOffset + count;
  const size_t len = read_end_pos > cur_file_size ? cur_file_size : read_end_pos;
  
  memcpy(buf, cur_file + FileDescriptor[fd].FileOffset, len - FileDescriptor[fd].FileOffset);

  free(cur_block);
  cur_block = NULL;

  free(cur_file);
  cur_file = NULL;
  return len;
}
