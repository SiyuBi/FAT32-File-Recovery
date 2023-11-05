#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20
#define MAX_PERMUTATION_NUMBER 21

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

int next_cluster(void *mapped_disk, BootEntry* bs, int cluster){
    // FAT entry for the current cluster
    uint32_t current_cluster = bs->BPB_RsvdSecCnt * bs->BPB_BytsPerSec + cluster * 4;
    // Read entry
    uint32_t *fat_entry_ptr = (uint32_t *)((char *)mapped_disk + current_cluster);
    // printf("fat_entry_ptr %d\n", *fat_entry_ptr);
    if (*fat_entry_ptr >= 0x0FFFFFF8){
        return -1;
    } else {
        return *fat_entry_ptr;
    }
}

uint32_t calculate_address(int cluster, BootEntry* bs){
    return (bs->BPB_RsvdSecCnt + bs->BPB_NumFATs * bs->BPB_FATSz32 + (cluster - 2) * bs->BPB_SecPerClus)* bs->BPB_BytsPerSec;
}

void printUsage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

void convert_to_83_format(const char *input, char *output) {
    int i = 0;
    int j = 0;
    int end_of_name = 0;
    while (i < 8){
        if (end_of_name == 1) {
            output[i] = ' ';
            i++;
            continue;
        }
        if (input[i] == '.') {
            end_of_name = 1;
            output[i] = ' ';
            i++;
            j++;
            continue;
        }
        output[i] = toupper(input[i]);
        i++;
        j++;
    }
    while (i < 11){
        if ((size_t)j >= strlen(input)) {
            output[i] = ' ';
        } else {
            output[i] = toupper(input[j]);
        }
        j++;
        i++;
    }
    output[11] = '\0';
}

void convert_to_normal_format(unsigned char *input, char *output){
    int i = 0;
    int j = 0;
    int end_of_name = 0;
    while (i < 8){
        // printf("input[i] %c\n", input[i]);
        if (end_of_name){
            i++;
            continue;
        }
        if (input[i] == ' ') {
            end_of_name = 1;
            output[j] = '.';
            i++;
            j++;
            continue;
        }
        output[j] = toupper(input[i]);
        i++;
        j++;
    }
    if (input[i-1] != ' '){
        output[j] = '.';
        j++;
    }
    if (input[i] == ' '){
        output[j-1] = '\0';
        return;
    }
    while (i < 11){
        if (input[i] == ' '){
            j++;
            i++;
            break;
        }
        output[j] = toupper(input[i]);
        j++;
        i++;
    }
    output[j] = '\0';
}

int main(int argc, char *argv[]) {
    int opt;
    int wrongInput = 1;
    char* filename;
    // char *sha1;
    int disk_fd = open(argv[1], O_RDWR);
    // FILE *disk_file = fdopen(disk_fd, "r");
    
    //disk info
    if (disk_fd < 0) {
        printUsage();
        exit(EXIT_FAILURE);
    }
    struct stat disk_stat;
    if (fstat(disk_fd, &disk_stat) < 0) {
        perror("Error getting file size");
        close(disk_fd);
        exit(EXIT_FAILURE);
    }
    void *mapped_disk = mmap(NULL, disk_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, disk_fd, 0);
    if (mapped_disk == MAP_FAILED) {
        perror("Error mapping disk file");
        close(disk_fd);
        exit(EXIT_FAILURE);
    }
    BootEntry *bs = (BootEntry *)mapped_disk;
    uint32_t cluster_size = bs->BPB_BytsPerSec * bs->BPB_SecPerClus;

    //root dir
    uint32_t root_directory_start = (bs->BPB_RsvdSecCnt + bs->BPB_NumFATs * bs->BPB_FATSz32) * bs->BPB_BytsPerSec;
    DirEntry *root_dir = (DirEntry *)((unsigned char *)mapped_disk + root_directory_start);
    int next_root_cluster;

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
                wrongInput = 0; 
                printf("Number of FATs = %u\n", bs->BPB_NumFATs);
                printf("Number of bytes per sector = %u\n", bs->BPB_BytsPerSec);
                printf("Number of sectors per cluster = %u\n", bs->BPB_SecPerClus);
                printf("Number of reserved sectors = %u\n", bs->BPB_RsvdSecCnt);
                break;
            case 'l':
                // printf("%ld\n",bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry));
                next_root_cluster = bs->BPB_RootClus;
                // printf("calculate_address %s\n", calculate_address(mapped_disk, next_root_cluster, bs));
                wrongInput = 0; 
                size_t file_count = 0;
                int entry_count = 0;
                root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                while (next_root_cluster != -1 && root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] != 0xE5) {
                            char* converted_filename = malloc(11);
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            if (!(root_dir->DIR_Attr & 0x10)) { // not a directory
                                printf("%s (size = %u", converted_filename, root_dir->DIR_FileSize);
                                if (root_dir->DIR_FileSize > 0 || (root_dir->DIR_Attr & 0x10)){
                                    printf(", starting cluster = %u", (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO);
                                }
                                printf(")\n");
                            } else {
                                printf("%s/ (starting cluster = %u)\n", converted_filename, (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO);
                            }
                            free(converted_filename);
                            file_count++;
                        }
                        entry_count++;
                        root_dir++;
                        // printf("%ld\n",entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)));
                        //next cluster
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                }
                printf("Total number of entries = %zu\n", file_count);
                break;
            case 'r':
                wrongInput = 0; 
                //find entry
                //get filename as argument to -r
                filename = optarg;
                char* converted_filename = malloc(12);
                convert_to_83_format(filename, converted_filename);
                entry_count = 0;
                int found = 0;
                //https://stackoverflow.com/questions/41109861/sha1-example-in-c-using-openssl-library
                if (getopt(argc, argv, "ilr:R:s:") == 's'){
                    unsigned char* reference_sha1 = (unsigned char*)optarg;
                    next_root_cluster = bs->BPB_RootClus;
                    root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    while (next_root_cluster != -1 && root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            char* converted_input_filename = malloc(12);
                            memcpy(converted_input_filename, filename, 11);
                            converted_input_filename[0] = (unsigned char) 0xE5;
                            if (strncmp(converted_input_filename, converted_filename, strlen(converted_filename)) == 0){
                                //file
                                uint32_t current_cluster_number = (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                uint32_t current_cluster = calculate_address(current_cluster_number, bs);

                                //sha1
                                unsigned char file_sha1[SHA_DIGEST_LENGTH];
                                SHA_CTX ctx;
                                SHA1_Init(&ctx);
                                unsigned char * file_ptr = ((unsigned char *)mapped_disk + current_cluster);
                                // printf("file_size %d, %d clusters\n", root_dir->DIR_FileSize,cluster_size);
                                for (size_t i = 0; i < root_dir->DIR_FileSize/cluster_size+1; i++) {
                                    size_t size = root_dir->DIR_FileSize-i*cluster_size >= cluster_size ? cluster_size : root_dir->DIR_FileSize-i*cluster_size;
                                    // printf("file %s: %s\n",converted_filename, file_ptr + i*cluster_size);
                                    SHA1_Update(&ctx, file_ptr + i*cluster_size, size);
                                }

                                SHA1_Final(file_sha1, &ctx);

                                char file_sha1_str[SHA_DIGEST_LENGTH];
                                for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                                    sprintf(&file_sha1_str[i*2], "%02x", file_sha1[i]);
                                }
                                // printf("file_sha1_str %s\n", file_sha1_str);
                                if (memcmp(file_sha1_str, reference_sha1, SHA_DIGEST_LENGTH) == 0){
                                    found = 1;
                                    //exit
                                    break;
                                }
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }
                    if (!found){
                        printf("%s: file not found\n", filename);
                        exit(EXIT_FAILURE);
                    }

                    // leave the pointers where they are
                    // next_root_cluster = bs->BPB_RootClus;
                    // root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    entry_count = 0;
                    while (root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            // printf("converted_filename %send\n", converted_filename);
                            // //check if the filename matches
                            // printf("strlen %ld\n", strlen(converted_filename+1));
                            if (strncmp(filename+1, converted_filename+1, strlen(converted_filename) - 1) == 0){
                        
                                found = 1;
                                //recover filename
                                root_dir->DIR_Name[0] = filename[0];
                                if (root_dir->DIR_FileSize > 0){
                                    // Recover FAT
                                    uint32_t fat_start_offset = bs->BPB_RsvdSecCnt * bs->BPB_BytsPerSec;
                                    uint32_t fat_size = bs->BPB_FATSz32 * bs->BPB_BytsPerSec;
                                    // uint32_t* currentCluster = &(root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                    for (uint32_t fat_index = 0; fat_index < bs->BPB_NumFATs; fat_index++) {
                                        uint32_t total_clusters_looped = 0;
                                        uint32_t current_fat_offset = fat_start_offset + fat_index * fat_size;
                                        // printf("recovered 1 at %d\n",current_fat_offset);
                                        uint32_t cluster = (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                        while (total_clusters_looped*cluster_size < root_dir->DIR_FileSize) {
                                            uint32_t current_cluster = current_fat_offset + cluster * 4;
                                            // Calculate the offset of the current FAT
                                            uint32_t *fat_entry_ptr = (uint32_t *)((char *)mapped_disk + current_cluster);
                                            // // update
                                            cluster ++;
                                            *fat_entry_ptr = cluster;

                                            total_clusters_looped ++;
                                            // // final cluster
                                            if (total_clusters_looped * cluster_size >= root_dir->DIR_FileSize){
                                                *fat_entry_ptr = 0x0FFFFFFF;
                                                break;
                                            }
                                        }
                                        if (msync(mapped_disk, fat_size, MS_SYNC) == -1) {
                                            perror("msync");
                                        }
                                    }
                                }
                                printf("%s: successfully recovered with SHA-1\n", filename);
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }
                }
                else{
                    next_root_cluster = bs->BPB_RootClus;
                    root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    while (next_root_cluster != -1 && root_dir->DIR_Name[0] != 0x00) {
                        // printf("converted_filename %s\n", dir->DIR_Name);
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            //check if the filename matches
                            // printf("found %d\n", found);
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            char* converted_input_filename = malloc(12);
                            memcpy(converted_input_filename, filename, 11);
                            converted_input_filename[0] = (unsigned char) 0xE5;
                            // printf("converted_input_filename %s\n", converted_input_filename);
                            // printf("converted_filename %s\n", converted_filename);
                            //compare whichever is longer
                            int compare_length = strlen(converted_filename);
                            if (strlen(converted_filename) < strlen(converted_input_filename)){
                                compare_length = strlen(converted_input_filename);
                            }
                            if (strncmp(converted_input_filename, converted_filename, compare_length) == 0){
                                found ++;
                                if (found > 1) {
                                    printf("%s: multiple candidates found\n", filename);
                                    exit(EXIT_FAILURE);
                                }
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }

                    //reset counts
                    next_root_cluster = bs->BPB_RootClus;
                    root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    entry_count = 0;
                    while (root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            // printf("converted_filename %send\n", converted_filename);
                            // //check if the filename matches
                            // printf("strlen %ld\n", strlen(converted_filename+1));
                            char* converted_input_filename = malloc(12);
                            memcpy(converted_input_filename, filename, 11);
                            converted_input_filename[0] = (unsigned char) 0xE5;
                            int compare_length = strlen(converted_filename);
                            if (strlen(converted_filename) < strlen(converted_input_filename)){
                                compare_length = strlen(converted_input_filename);
                            }
                            if (strncmp(converted_input_filename, converted_filename, compare_length) == 0){
                                found = 1;
                                //recover filename
                                root_dir->DIR_Name[0] = filename[0];
                                if (root_dir->DIR_FileSize > 0){
                                    // Recover FAT
                                    uint32_t fat_start_offset = bs->BPB_RsvdSecCnt * bs->BPB_BytsPerSec;
                                    uint32_t fat_size = bs->BPB_FATSz32 * bs->BPB_BytsPerSec;
                                    uint32_t cluster_size = bs->BPB_BytsPerSec * bs->BPB_SecPerClus;
                                    // uint32_t* currentCluster = &(root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                    for (uint32_t fat_index = 0; fat_index < bs->BPB_NumFATs; fat_index++) {
                                        uint32_t total_clusters_looped = 0;
                                        uint32_t current_fat_offset = fat_start_offset + fat_index * fat_size;
                                        // printf("recovered 1 at %d\n",current_fat_offset);
                                        uint32_t cluster = (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                        while (total_clusters_looped*cluster_size < root_dir->DIR_FileSize) {
                                            uint32_t current_cluster = current_fat_offset + cluster * 4;
                                            // Calculate the offset of the current FAT
                                            uint32_t *fat_entry_ptr = (uint32_t *)((char *)mapped_disk + current_cluster);
                                            // // update
                                            cluster ++;
                                            *fat_entry_ptr = cluster;

                                            total_clusters_looped ++;
                                            // // final cluster
                                            if (total_clusters_looped * cluster_size >= root_dir->DIR_FileSize){
                                                *fat_entry_ptr = 0x0FFFFFFF;
                                                break;
                                            }
                                        }
                                        if (msync(mapped_disk, fat_size, MS_SYNC) == -1) {
                                            perror("msync");
                                        }
                                    }
                                }
                                printf("%s: successfully recovered\n", filename);
                                exit(EXIT_SUCCESS);
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }
                }
                if (!found){
                    printf("%s: file not found\n", filename);
                }
                break;
            case 'R':
                wrongInput = 0;
                filename = optarg;
                converted_filename = malloc(12);
                convert_to_83_format(filename, converted_filename);
                entry_count = 0;
                found = 0;
                if (getopt(argc, argv, "ilr:R:s:") == 's'){
                    unsigned char* reference_sha1 = (unsigned char*)optarg;
                    next_root_cluster = bs->BPB_RootClus;
                    root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    int* permutation = malloc(5*sizeof(int));
                    while (next_root_cluster != -1 && root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            char* converted_input_filename = malloc(12);
                            memcpy(converted_input_filename, filename, 11);
                            converted_input_filename[0] = (unsigned char) 0xE5;
                            int compare_length = strlen(converted_filename);
                            if (strlen(converted_filename) < strlen(converted_input_filename)){
                                compare_length = strlen(converted_input_filename);
                            }
                            if (strncmp(converted_input_filename, converted_filename, compare_length) == 0){
                                //sha1
                                unsigned char file_sha1[SHA_DIGEST_LENGTH];
                                char file_sha1_str[SHA_DIGEST_LENGTH];
                                unsigned char * file_ptr = ((unsigned char *)mapped_disk + calculate_address(0, bs));
                                permutation[0] = (root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                // permutation[0] = 7;
                                // printf("filename %s\n", root_dir->DIR_Name);
                                // printf("permutation[0] %d\n", permutation[0]);
                                int num_file_clusters = root_dir->DIR_FileSize/cluster_size+1;
                                size_t size = root_dir->DIR_FileSize-permutation[0]*cluster_size >= cluster_size ? cluster_size : root_dir->DIR_FileSize-permutation[0]*cluster_size;
                                for (int a = 2; a <= MAX_PERMUTATION_NUMBER; a++){
                                    if(found){
                                        break;
                                    }
                                    if (a == permutation[0]){
                                        continue;
                                    }
                                    permutation[1] = a;
                                    for (int b = 2; b <= MAX_PERMUTATION_NUMBER; b++){
                                        if (found){
                                            break;
                                        }
                                        if (b == a || b == permutation[0]){
                                            continue;
                                        }
                                        permutation[2] = b;
                                        for (int c = 2; c <= MAX_PERMUTATION_NUMBER; c++){
                                            if (found){
                                                break;
                                            }
                                            if (c == a || c == b || c == permutation[0]){
                                                continue;
                                            }
                                            permutation[3] = c;
                                            for (int d = 2; d <= MAX_PERMUTATION_NUMBER; d++){
                                                if (found){
                                                    break;
                                                }
                                                if (d == a || d == b || d == c || d == permutation[0]){
                                                    continue;
                                                }
                                                permutation[4] = d;

                                                size = root_dir->DIR_FileSize >= cluster_size ? cluster_size : root_dir->DIR_FileSize%cluster_size;
                                                // printf("permutation size %d\n", num_file_clusters);
                                                // printf("permutation %d %d %d %d %d\n", permutation[0], permutation[1], permutation[2], permutation[3], permutation[4]);
                                                // printf("size %d\n", root_dir->DIR_FileSize%cluster_size);
                                                // printf("file: %s\n",file_ptr + permutation[0]*cluster_size);
                                                SHA_CTX ctx;
                                                SHA1_Init(&ctx);
                                                SHA1_Update(&ctx, file_ptr + permutation[0]*cluster_size, size);

                                                for (int i = 1; i < num_file_clusters; i++) {
                                                    size = root_dir->DIR_FileSize-i*cluster_size >= cluster_size ? cluster_size : root_dir->DIR_FileSize-i*cluster_size;
                                                    // printf("size %ld\n", size);
                                                    // printf("file: %s\n",file_ptr + permutation[i]*cluster_size);
                                                    SHA1_Update(&ctx, file_ptr + permutation[i]*cluster_size, size);
                                                }
                                                SHA1_Final(file_sha1, &ctx);
                                                for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                                                    sprintf(&file_sha1_str[i*2], "%02x", file_sha1[i]);
                                                }
                                                // printf("file_sha1_str %s\n", file_sha1_str);
                                                if (memcmp(file_sha1_str, reference_sha1, SHA_DIGEST_LENGTH) == 0){
                                                    // printf("matched\n");
                                                    found = 1;
                                                    goto recover_fat;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }
                    if (!found){
                        printf("%s: file not found\n", filename);
                        exit(EXIT_FAILURE);
                    }
                    recover_fat:
                    // leave the pointers where they are
                    next_root_cluster = bs->BPB_RootClus;
                    root_dir =  (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                    entry_count = 0;
                    while (root_dir->DIR_Name[0] != 0x00) {
                        if (root_dir->DIR_Name[0] == 0xE5) {
                            convert_to_normal_format(root_dir->DIR_Name, converted_filename);
                            char* converted_input_filename = malloc(12);
                            memcpy(converted_input_filename, filename, 11);
                            converted_input_filename[0] = (unsigned char) 0xE5;
                            int compare_length = strlen(converted_filename);
                            if (strlen(converted_filename) < strlen(converted_input_filename)){
                                compare_length = strlen(converted_input_filename);
                            }
                            if (strncmp(filename+1, converted_filename+1, compare_length) == 0){
                        
                                found = 1;
                                //recover filename
                                root_dir->DIR_Name[0] = filename[0];
                                if (root_dir->DIR_FileSize > 0){
                                    // Recover FAT
                                    uint32_t fat_start_offset = bs->BPB_RsvdSecCnt * bs->BPB_BytsPerSec;
                                    uint32_t fat_size = bs->BPB_FATSz32 * bs->BPB_BytsPerSec;
                                    // uint32_t* currentCluster = &(root_dir->DIR_FstClusHI << 16) | root_dir->DIR_FstClusLO;
                                    for (uint32_t fat_index = 0; fat_index < bs->BPB_NumFATs; fat_index++) {
                                        uint32_t current_fat_offset = fat_start_offset + fat_index * fat_size;
                                        // printf("recovered 1 at %d\n",current_fat_offset);
                                        uint32_t cluster = permutation[0];
                                        int i = 0;
                                        while (permutation[i]) {
                                            uint32_t current_cluster = current_fat_offset + cluster * 4;
                                            // Calculate the offset of the current FAT
                                            uint32_t *fat_entry_ptr = (uint32_t *)((char *)mapped_disk + current_cluster);
                                            // // update
                                            i++;
                                            cluster = permutation[i];
                                            *fat_entry_ptr = cluster;

                                            // // final cluster
                                            if (!permutation[i]){
                                                *fat_entry_ptr = 0x0FFFFFFF;
                                                break;
                                            }
                                        }
                                        if (msync(mapped_disk, fat_size, MS_SYNC) == -1) {
                                            perror("msync");
                                        }
                                    }
                                }
                                printf("%s: successfully recovered with SHA-1\n", filename);
                            }
                        }
                        entry_count++;
                        root_dir++;
                        if (entry_count % (bs->BPB_BytsPerSec * bs->BPB_SecPerClus / sizeof(DirEntry)) == 0){
                            next_root_cluster = next_cluster(mapped_disk, bs, next_root_cluster);
                            root_dir = (DirEntry *)((unsigned char *)mapped_disk + calculate_address(next_root_cluster, bs));
                        }
                    }
                }
                break;
            default:
                break;
        }
    }
    if (wrongInput){
        printUsage();
    }
    
    // fclose(disk_file);
    close(disk_fd);
    
}
