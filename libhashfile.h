#ifndef _HASHFILELIB_H
#define _HASHFILELIB_H

#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>

enum chnking_method{
    FIXED = 1,
    VARIABLE = 2
};
enum hshing_method{
    MD5_HASH = 1,
    SHA256_HASH = 2,
    MD5_48BIT_HASH = 3, //UBC trace
    MURMUR_HASH = 4,
    MD5_64BIT_HASH = 5,
    SHA1_HASH = 6
};
enum var_chnking_algo{
    RANDOM = 1,
    SIMPLE_MATCH = 2,
    RABIN = 3 //UBC trace
};

struct fixed_chnking_params{
    uint32_t chunk_size;
}__attribute__((packed));
struct var_rabin_chnk_params{ //I don't know the settings of params in UBC. 
    uint32_t window_size; 
    uint64_t prime;
    uint64_t module;
    uint32_t bits_to_compare;
    uint64_t pattern;
}__attribute__((packed));
struct var_chnking_params{
    enum var_chnking_algo algo;
    union{
        struct var_rabin_chnk_params rabin_params;
    }algo_params;
    uint32_t min_csize; //in bytes
    uint32_t max_csize; //in bytes
}__attribute__((packed));
enum scanning_method{
    STANDARD = 1,
    BACKUP = 2
};
struct hashfile_metadata {
    enum scanning_method scan_method;
    char username[14];
    char hostname[14];
    char sys_dir[21];
    uint64_t cur_time;
    enum chnking_method chnk_method;
    union {
        struct fixed_chnking_params fixed_params;
        struct var_chnking_params var_params;
    }chnk_method_params;
    enum hshing_method hsh_method;
    char OS[255];
}__attribute__((packed));
/* refer to
 * UBC per file format
 * */
struct abstract_file_header {
    char dir_name[10]; //directory name
    int dir_length; //directory length
    char file_name[10]; 
    int file_length;
    char extensions[10];
    int ext_value;
    int namespace_depth;
    uint64_t file_size;
    char attr_flags[10];
    uint64_t file_id;
    int hardlinks;
    char reparse_flags[10];
    uint64_t ctime; //creation time
    uint64_t atime; //access time
    uint64_t mtime; //modification time
    int chunks; //number of chunks
};

struct chunk_info {
    char *hash; //10-bit hash of data, and 12-bit 'z'?
    int size;
    uint8_t cratio;
}__attribute__((packed));

struct hashfile_handle {
    int fd; //file descriptor
    struct hashfile_metadata metadata;
    struct abstract_file_header current_file;
    struct chunk_info current_chunk_info;
    uint64_t num_files_processed;
    uint64_t num_hashes_processed_current_files;
};

struct hashfile_handle *hashfile_open(char *hashfile_name);
uint64_t hashfile_start_time(struct hashfile_handle *handle);
uint64_t hashfile_end_time(struct hashfile_handle *handle);
int split_line(struct hashfile_handle *handle, char *buffer);
int get_key_value(struct hashfile_handle *handle, char *key, int key_size, 
        int *value);
int get_char_value(struct hashfile_handle *handle, char *value);
int get_int_value(struct hashfile_handle *handle, int *value);
int get_uint64_value(struct hashfile_handle *handle, uint64_t *value);
int Cur_part_end(struct hashfile_handle *handle);
int hashfile_next_file(struct hashfile_handle *handle);
const struct chunk_info *hashfile_next_chunk(struct hashfile_handle *handle);
uint64_t hashfile_curfile_size(struct hashfile_handle *handle);
int chunk_hash_size(struct chunk_info *ci);
void hashfile_close(struct hashfile_handle *handle);
char* get_time(struct hashfile_handle *handle);
char* get_hostname(struct hashfile_handle *handle);
char* get_OS(struct hashfile_handle *handle);
/*
* handle directory
*/
char* parse_file_dir(char *path);
char* hashfile_name(char *dir, int len, int hashfile_count);
#endif /*_HASHFILELIB_H_*/
