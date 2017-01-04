/*
 * collect UBC tracefile
 * */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <openssl/md5.h>

#include "data.h"
#include "store.h"
#include "libhashfile.h"

#define MAXLINE 4096

static void print_chunk_hash(uint64_t chunk_count, const uint8_t *hash, 
        int hash_size_in_bytes)
{
    int j;

    printf("Chunk %06"PRIu64": ", chunk_count);

    printf("%.2hhx", hash[0]);
    for (j=1; j < hash_size_in_bytes; j++)
        printf(":%.2hhx", hash[j]);
    printf("\n");
}
static char* parse_file_dir(char *path){
    int i = strlen(path) -1;
    if(path[i] != '/'){
        path[i+1] = '/';
    }
    return path;
}
static char* hashfile_name(char *dir, int len,  int hashfile_count){
    char* file_name = dir;
    //printf("dir %s\n", dir);
    sprintf(file_name+len, "%04d", hashfile_count);
    return file_name;
}
static int read_hashfile(char *hashfile_dir, int csize, char *cmeth, int count)
{
    struct hashfile_handle *handle;
    int ret;
    int dir_len = strlen(hashfile_dir);
    struct chunk_rec chunk;
    int list[2];
    struct container_rec container;
    struct region_rec region;
    struct file_rec file;
    int64_t syssize = 0;
    int64_t dupsize = 0;

    /* statistics for generating IDs
     * ID starts from 0 */
    int chunk_count = 0;
    int container_count = 0;
    int region_count = 0;
    int file_count = 0;
    int empty_files = 0;
    int dup_count = 0;
    int hashfile_count = 1;
    
    for (; hashfile_count <= count; hashfile_count++){
        memset(&chunk, 0, sizeof(chunk));
        chunk.list = list;
        memset(&container, 0, sizeof(container));
        memset(&region, 0, sizeof(region));
        char *Hashfile_Name = hashfile_name(hashfile_dir, dir_len, hashfile_count);
        printf("%s\n", Hashfile_Name);
        handle = hashfile_open(Hashfile_Name);
	//ret = lseek(handle->fd, 0, SEEK_CUR);        
	//printf("ret metadata %d\n", ret);
        if (!handle){
            fprintf(stderr, "Error opening hash file: %d!", errno);
            return -1;
        }
        if (cmeth[0] == 'f') {
            handle->metadata.chnk_method = FIXED;
            handle->metadata.chnk_method_params.fixed_params.chunk_size = csize; 
        } 
        else if(cmeth[0] == 'v') { 
            handle->metadata.chnk_method = VARIABLE;
        }
        
        /* Go over the files in the hashfile*/
        while(1){
            ret = hashfile_next_file(handle);
	    //printf("file 1 end %d\n", ret);
            if (ret < 0) {
                fprintf(stderr, "Cannot get next file from a hashfile: %d.\n",errno);
                return -1;
            }
            /* exit the loop if it is the last file*/
            if (ret == 0)
                break;

            /* file start*/
            //printf("dir_name:%s dir_length:%d\nfile_name %s file_size %d\n", handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_size);
            memset(&file, 0 ,sizeof(file));
            memset(&file.minhash, 0xff, sizeof(file.minhash));//don't know what it is, and where is maxhash?
            file.fid = file_count;

            file.fname = malloc(strlen(handle->current_file.file_name)+1);
            strcpy(file.fname, handle->current_file.file_name);
            //printf("file_name: %s\n", handle->current_file.file_name);
            printf("%d:%s, %"PRIu64"\n", file.fid, handle->current_file.file_name, hashfile_curfile_size(handle));

            MD5_CTX ctx;
            MD5_Init(&ctx);
            int all_chunk_size = 0;
            while(1){
                const struct chunk_info *ci;
                ci = hashfile_next_chunk(handle);
                if(!ci)/* exit the loop if it was the last chunk */
                    break;
                printf("chunk %s: %d\n", ci->hash, ci->size);
                int hashsize = chunk_hash_size(ci);
                int chunksize = ci->size;
                memcpy(chunk.hash, ci->hash, hashsize);
                memcpy(&chunk.hash[hashsize], &chunksize, sizeof(chunksize));
                /* new hash = hash(chunk_hash, chunk_size)*/
                chunk.hashlen = hashsize + sizeof(chunksize);

                MD5_Update(&ctx, chunk.hash, chunk.hashlen);
		
		/* also don't know why */

            	if(memcmp(chunk.hash, file.minhash, chunk.hashlen) < 0){
                    memcpy(file.minhash, chunk.hash, chunk.hashlen);
            	}
            
            	if(memcmp(chunk.hash, file.maxhash, chunk.hashlen) > 0){
                    memcpy(file.maxhash, chunk.hash, chunk.hashlen);
                }

                ret = search_chunk_local(&chunk);
                if(ret == 0){
                    chunk.csize = ci->size;
                    chunk.cratio = 0;//UBC Trace don't have compression ratio
                    
                    /* TO-DO: write to the open region */
                    while(add_chunk_to_region(&chunk, &region) != 1){
                        /* the last region is full, write it to the open container*/

                        add_region_to_container(&region, &container);
                        region_count++;

                        /* open a new region*/
                        reset_region_rec(&region);
                        region.rid = region_count;

                        if(container_full(&container)){
                            container_count++;

                            reset_container_rec(&container);
                            container.cid = container_count;
                        }
                    }
                    
                    chunk.rid = region.rid;
                    chunk.cid = container.cid;
                }else if(ret == 1){
                    /* A duplicate chunk*/
                    dup_count++;
                    dupsize += chunk.csize;

                    if(chunk.csize != ci->size){
                        print_chunk_hash(chunk_count, chunk.hash, chunk_hash_size(ci));//modify later
                        printf("Hash Collision: %d to %d\n", chunk.csize, ci->size);
                    }
                }else {
                    exit(2);
                }
                syssize += chunk.csize;
                chunk.list[0] = chunk_count;
                chunk.list[1] = file_count;
                
                update_chunk(&chunk);

                /* update file info */
                file.cnum++;
                file.fsize += chunk.csize;

                chunk_count++;
            }

            MD5_Final(file.hash, &ctx);

            if(file.fsize != hashfile_curfile_size(handle))
                printf("%"PRId64" != %"PRIu64"\n", file.fsize, hashfile_curfile_size(handle));
            /* file end; update it */
            if(file.fsize > 0){
                update_file(&file);
                file_count++;
            }else{
                empty_files++;
            }
	    
            free(file.fname);
            file.fname = NULL;
        }
        hashfile_close(handle);
    }
    printf("%.2fGB bytes in total, eliminating %.2fGB bytes, %.5f, %.5f\n", 1.0*syssize/1024/1024/1024, 1.0*dupsize/1024/1024/1024, 1.0*dupsize/syssize, 1.0*syssize/(syssize-dupsize));
    printf("%d duplicate chunks out of %d\n", dup_count, chunk_count);
    printf("%d files, excluding %d empty files\n", file_count, empty_files);
    return 0;
}

int main(int argc, char *argv[])
{
    create_database();
    /*
     * ./collector [chunking_size: 8, 16,..] [chunking_method: f/v]  [dir] [count] 
     * */
    int chnking_size = (int)strtol(argv[1], NULL, 10);
    char *dir = parse_file_dir(argv[3]);
    int len = strlen(dir);
    int num_files = (int)strtol(argv[4], NULL, 10);
    /*int i = 1;
    for( ; i <= num_files; i++){
        char *res = hashfile_name(dir, len, i);
        printf("%s\n", res);
    }*/
    int ret = read_hashfile(dir, chnking_size, argv[2], num_files);
    
    close_database();
    
    return 0;
}
