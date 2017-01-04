#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <time.h>
#include "libhashfile.h"
#define MAX_B 255

int split_line(struct hashfile_handle *handle, char *buffer){
    /*go to the beginning of the nextline*/
    int ret = 0;
    int i;
    int len = strlen(buffer);
    for(i = 0; i < len; i++){
        if(buffer[i] == '\r' && buffer[i+1] == '\n'){
            //printf("length %d\n", len);
            ret = lseek(handle->fd, 0, SEEK_CUR);
            //printf("ret11 %d\n", ret);
            //printf("offset %d\n", ret-len+i+2);
            ret = lseek(handle->fd, (off_t)-len+i+2, SEEK_CUR);
            //printf("ret22 %d\n", ret);
            break;
        }
    }
    return ret;
}
int get_char_value(struct hashfile_handle *handle, char *value){
    int ret = 0;
    char buffer[MAX_B] = "";
    ret = read(handle->fd, buffer, sizeof(buffer));
    int i;
    int len = strlen(buffer);
    for(i = 0; i < len; i++){
        if(buffer[i] == '\r'){
           ret = lseek(handle->fd, (off_t)-len+i+2, SEEK_CUR);    
           break;
        }
        value[i] = buffer[i];
        //ret = split_line(handle, buffer);
    }
    value[i] = '\0';
    return ret;
}
int get_int_value(struct hashfile_handle *handle, int *value){
    int ret;
    char buffer[MAX_B] = "";
    //printf("11 length of buffer %d, size of buffer %d\n", strlen(buffer), (int)sizeof(buffer));
    ret = read(handle->fd, buffer, sizeof(buffer));
    //printf("buffer?? %s\n", buffer);
    /*if(strlen(buffer) < sizeof(buffer)){
        printf("read bytes:%d\nbuffer: %s\n", (int)strlen(buffer), buffer); 
        printf("Will end of file\n");
    }*/
    //printf("11 length of buffer %d, size of buffer %d\n", strlen(buffer), (int)sizeof(buffer));
    if(strlen(buffer) > (int)sizeof(buffer))
        buffer[MAX_B] = '\0';
    *value = (int)strtol(buffer, NULL, 10);
    //assert(strlen(buffer) <= (int)sizeof(buffer));
    ret = split_line(handle, buffer);
    //printf("ret33 %d\n", ret);
    return ret;
}
int get_uint64_value(struct hashfile_handle *handle, uint64_t *value){
    int ret;
    char buffer[MAX_B] = "";
    ret = read(handle->fd, buffer, sizeof(buffer));
    //printf("====== will to time %s\n", buffer);
    *value = (uint64_t)strtoull(buffer, NULL, 10);
    /*if(*value == 0){
        printf("====== time %s\n", buffer);
    }*/
    ret = split_line(handle, buffer);
    return ret;
}
int get_key_value(struct hashfile_handle *handle, char *key, int key_size,
        int *value){
    char buffer[MAX_B] = "";
    int ret;  
    ret = read(handle->fd, key, key_size);
    ret = lseek(handle->fd, 1, SEEK_CUR);
    ret = get_int_value(handle, value);
    return ret;
}

int Cur_part_end(struct hashfile_handle *handle){
    int ret;
    int flag_r = 0, flag_rn = 0, flag_rnr = 0;
    int end = 0;
    //printf("now cursor %d\n", (int)lseek(handle->fd, 0, SEEK_CUR));
    while(!end){
        char buffer[MAX_B] = "";
        ret = read(handle->fd, buffer, sizeof(buffer));
        //printf("ret %d\nbuffer_part %s\n", ret, buffer);
        int len = strlen(buffer);
        if(ret == 0){
            //printf("end of file\n");
            break;
        }
        int i;
        for(i = 0; i < len; i++){
            if(i == 0){
                if(flag_r == 1){
		    if(buffer[i] == '\n' && buffer[i+1] == '\r' && buffer[i+2] == '\n'){
                        flag_r = 0;
                        ret = lseek(handle->fd, (off_t)-len+3, SEEK_CUR);
                        //printf("====r+nrn\n");
                        end = 1;
                        break;
		    }else{
		        flag_r = 0;
		    }
                }else if(flag_rn == 1){
		    if(buffer[i] == '\r' && buffer[i+1] == '\n'){
                        flag_rn = 0;
		        //printf("***===****%c%c%c%c\n",buffer[i],buffer[i+1], buffer[i+2], buffer[i+3]);
		        ret = lseek(handle->fd, (off_t)-len+2, SEEK_CUR);
                        //printf("====rn+rn\n");
		        end = 1;
                        break;
                    }else{
                         flag_rn = 0;
                    }
                }else if(flag_rnr = 1){
                    if(buffer[i] == '\n'){
                    	flag_rnr = 0;
                    	//printf("***===****%c%c%c%c\n",buffer[i],buffer[i+1], buffer[i+2], buffer[i+3]);
                        ret = lseek(handle->fd, (off_t)-len+1, SEEK_CUR);
                        //printf("====rnr+n\n");
                        end = 1;
                        break;
                    }else{
                    	flag_rnr = 0;
                    }
                }
            }else if(i < len-3 && buffer[i] == '\r' && buffer[i+1] == '\n'
                   && buffer[i+2] =='\r' && buffer[i+3] == '\n' ){
                //printf("***===****%c%c%c%c%c%c\n",buffer[i-2],buffer[i-1], buffer[i],buffer[i+1], buffer[i+2], buffer[i+3]);
                ret = lseek(handle->fd, (off_t)-len+i+4, SEEK_CUR);
		//printf("====rnrn\n");                
		        end = 1;
                break;
            }else if(i == len-3 && buffer[i] == '\r' && buffer[i+1] == '\n'
                    && buffer[i+2] == '\r'){
                flag_rnr = 1;
            }else if(i == len-2 && buffer[i] == '\r' && buffer[i+1] == '\n'){
                flag_rn = 1;
            }else if(i == len-1 && buffer[i] == '\r'){
                flag_r = 1;
            }
        }
	//flag_r = 0, flag_rn = 0, flag_rnr = 0;
    }
    //printf("ret_part %d\n", ret);
    return ret;
}
struct hashfile_handle *hashfile_open(char *hashfile_name)
{
    int fd;
    int ret;
    struct hashfile_handle *handle;
    int saved_errno = 0;
    char buffer[MAX_B] = "";
    handle = (struct hashfile_handle *)malloc(sizeof(*handle));
    if (!handle)
        goto out;
 
    fd = open(hashfile_name, O_RDONLY);
    if (fd < 0) {
        saved_errno = errno;
        goto free_handle;
    }
    handle->fd = fd;
    ret = read(fd, buffer, sizeof(buffer));
    if(ret != sizeof(buffer)){
        if(ret >= 0)
            saved_errno = EAGAIN;
        else
            saved_errno = errno;
        goto close_file;
    }
    if (buffer[0] == 'S'){
        handle->metadata.scan_method = STANDARD; 
    }
    else if (buffer[0] == 'B') {
        handle->metadata.scan_method = BACKUP;
    }
    ret = split_line(handle, buffer);
    //printf("split_line %d\n", ret);
    ret = get_char_value(handle, handle->metadata.username);
    //printf("username %s\n", handle->metadata.username);
    //printf("****ret %d\n", ret);
    ret = get_char_value(handle, handle->metadata.hostname);
    ret = get_char_value(handle, handle->metadata.sys_dir);
    ret = get_int_value(handle, &handle->metadata.cur_time);
    
    handle->metadata.hsh_method = MD5_48BIT_HASH;
    handle->current_file.chunks = 0;
    handle->num_files_processed = 0;
    handle->num_hashes_processed_current_files = 0;
    handle->current_chunk_info.hash = (char *)malloc(sizeof(char)*12);//modify later
    if (!handle->current_chunk_info.hash){
        saved_errno = errno;
        goto close_file; 
    }
    //printf("ret111 %d\n", ret);
    
    //printf("return end of metadata %d\n", ret);
   // printf("username: %s\nhostname: %s\nsys_dir: %s\ncur_time: %d\n", handle->metadata.username, handle->metadata.hostname, handle->metadata.sys_dir, handle->metadata.cur_time);
    ret = Cur_part_end(handle);
    //printf("metadata ret %d\n", ret);
    return handle;

close_file:
    close(fd);
free_handle:
    free(handle);
    errno = saved_errno;
out:
    return NULL;
}

int hashfile_next_file(struct hashfile_handle *handle){
    char buffer[MAX_B] = "";
    int ret;
    //printf("here\n");
    ret= read(handle->fd, buffer, sizeof(char)*11);
    //ret = lseek(handle->fd, 0, SEEK_CUR);
    //printf("buffer ret %d\n", ret);
    //printf("buffer %s\n",buffer);
    if(strcmp(buffer, "LOGCOMPLETE") == 0){
        //printf("END OF FILE\n");
        return 0;
    }else{
        ret = lseek(handle->fd, (off_t)-11, SEEK_CUR);
    }
    
    ret = get_key_value(handle, handle->current_file.dir_name, 
            sizeof(handle->current_file.dir_name), &handle->current_file.dir_length);
    //printf("%d: dir_name %s dir_length %d\n", ret, handle->current_file.dir_name, handle->current_file.dir_length);
    //assert(strcmp(handle->current_file.dir_name, "zzzzzzzzzz") < 0);
    //assert(strcmp(handle->current_file.dir_name, "0000000000") >= 0);
    ret = get_key_value(handle, handle->current_file.file_name, 
            sizeof(handle->current_file.file_name), &handle->current_file.file_length);
    //printf("file name %s\n", handle->current_file.file_name);
    ret = get_key_value(handle, handle->current_file.extensions, sizeof(handle->current_file.extensions), &handle->current_file.ext_value);
    //printf("%d: extensions %s ext_value: %d\n", ret, handle->current_file.extensions, handle->current_file.ext_value);
    ret = get_int_value(handle, &handle->current_file.namespace_depth);
    //printf("%d: namespace: %d\n", ret, handle->current_file.namespace_depth);
    ret = get_uint64_value(handle, &handle->current_file.file_size);
    //printf("%d: file_size: %"PRIu64"\n", ret, handle->current_file.file_size);
    assert(handle->current_file.file_size>=0);
    ret = get_char_value(handle, handle->current_file.attr_flags);
    //printf("%d: attr_flags: %s\n", ret, handle->current_file.attr_flags);
    ret = get_uint64_value(handle, &handle->current_file.file_id);
    //printf("%d: file_id: %"PRIu64"\n", ret, handle->current_file.file_id);
    ret = get_int_value(handle, &handle->current_file.hardlinks);
    ret = get_char_value(handle, handle->current_file.reparse_flags);
    //printf("hardlinks %d\nreparse_flags %s\n", handle->current_file.hardlinks, handle->current_file.reparse_flags);
    ret = get_uint64_value(handle, &handle->current_file.ctime);
    assert(handle->current_file.ctime != 0);
    ret = get_uint64_value(handle, &handle->current_file.atime);
    //assert(handle->current_file.atime != 0);
    //printf("ret_file1 %d\n", ret);
    ret = get_uint64_value(handle, &handle->current_file.mtime);
    //assert(handle->current_file.mtime != 0);
    //printf("ret_file2 %d\n", ret);
    //ret = lseek(handle->fd, 0, SEEK_CUR);
    //ret = Cur_part_end(handle);
    
    //printf("creation time:%"PRIu64"\naccess time:%"PRIu64"\nmodification time:%"PRIu64"\n", handle->current_file.ctime, handle->current_file.atime, handle->current_file.mtime);
    //sleep(1);
    return ret;
}

uint64_t hashfile_curfile_size(struct hashfile_handle *handle){
    return handle->current_file.file_size;
}
int chunk_hash_size(struct chunk_info *ci){
    return (int)strlen(ci->hash);
}
const struct chunk_info *hashfile_next_chunk(struct hashfile_handle *handle){
    int ret = 0;
    char buffer[MAX_B] = "";
    if(!hashfile_curfile_size(handle)){/* file_size == 0*/
	//printf("empty file!\n"); 
        ret = read(handle->fd, buffer, sizeof(buffer));
        if(buffer[0] == '\r' && buffer[1] =='\n'){// No Lcn, Vcn
            ret = lseek(handle->fd, (off_t)-strlen(buffer)+2, SEEK_CUR);
        }else{
            //printf("buffer**** %s\n", buffer);
            ret = lseek(handle->fd, (off_t)-strlen(buffer), SEEK_CUR);       
	    ret = Cur_part_end(handle);
            //printf("ret %d\n",ret);
        }
        return NULL;
    }
    
    
    while(1){
        memset(buffer, 0, sizeof(buffer));
        ret = read(handle->fd, buffer, sizeof(buffer));
        //printf("***buffer %s\n", buffer);
        if(buffer[0] == 'S' || buffer[0] == 'V' || buffer[0] == 'A'){
            //printf("buffer %s\n", buffer);
            //ret = lseek(handle->fd, 0, SEEK_CUR);
            //printf("ret1: %d\n", ret);
	    ret = split_line(handle, buffer);
	    //printf("ret2: %d\n", ret);
            continue;
        }else if(buffer[0] == '\r' && buffer[1] == '\n'){// handle exception: file_size is not 0, but no chunk
	    ret = split_line(handle, buffer);
            //printf("exception file, no chunk\n");
	    return NULL;	
	}
	else {
            ret = lseek(handle->fd, (off_t)-strlen(buffer), SEEK_CUR);
            int hash_size = 10;
            if(buffer[0] == 'z'){
                hash_size = 12;
            }else {hash_size = 10;}
            //printf("hash size %d\n", hash_size);
            ret = get_key_value(handle, handle->current_chunk_info.hash, hash_size, 
                    &handle->current_chunk_info.size);
            //printf("chunk_info %s: %d\n", handle->current_chunk_info.hash, handle->current_chunk_info.size);
            if(hash_size == 10){
		handle->current_chunk_info.hash[10] = '\0';
	    }
            if(hash_size == 12){
	        handle->current_chunk_info.hash[12] = '\0';
	    }
            //assert(strcmp(handle->current_chunk_info.hash, "00000000")>=0);
            //assert(strcmp(handle->current_chunk_info.hash, "zzzzzzzzzzzz")<=0);
            assert(handle->current_chunk_info.size != 0);
            break;
        }
    }
    return &handle->current_chunk_info;
}
void hashfile_close(struct hashfile_handle *handle){
    time_t curtime;
    int ret;

    free(handle->current_chunk_info.hash);
    close(handle->fd);
    free(handle);
}

/*
int read_hashfile(char **hashfile_name, int count){
    struct hashfile_handle *handle;
    int ret;
    int hashfile_count = 0;
    for(; hashfile_count < count; hashfile_count++){
        handle = hashfile_open(hashfile_name[hashfile_count]);
	int file_count = 0;
        //ret = lseek(handle->fd, 7408619, SEEK_SET);//2978
        
        //ret = hashfile_next_file(handle);
	//printf("file id:%d\ndir_name:%s dir_length:%d\nfile_name %s file_length %d\n", file_count, handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_length);
        //printf("ret %d\n", ret);
        //ret = hashfile_next_file(handle);
        while(1){
            printf("# %d\n", file_count);
            ret = hashfile_next_file(handle);
            //printf("reading file ret%d\n", ret);
            if(ret == 0)
            {
                printf("file counts: %d\n", file_count);
                break;
            }
            //printf("file no. %d\n", file_count);
            //int chunksize = 0;
	    //printf("dir_name:%s dir_length:%d\nfile_name %s file_size %"PRIu64"\n", handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_size);
            int filesize = 0;
	    while(1){
	        const struct chunk_info *ci;
                ci = hashfile_next_chunk(handle);
		if(!ci){
		    //printf("empty file\n");
                    break;
		}
		filesize += ci->size;
		printf("chunk %s: %d\n",handle->current_chunk_info.hash, handle->current_chunk_info.size);
               
                //printf("*****%s: %d\n", ci->hash, ci->size);
                //sleep(1);		
	   }
	    if(filesize != hashfile_curfile_size(handle))
		printf("%d != %"PRIu64"\n", filesize, hashfile_curfile_size(handle));
            //printf("dir_name:%s dir_length:%d\nfile_name %s file_size %d\n", handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_size);
            //printf("ret %d\n", ret);
            //sleep(5);
            file_count++;
        }
    }
    return ret;
}
int main(int argc, char *argv[]){
    int ret = read_hashfile(&argv[1], argc-1);
    printf("ret1 %d\n", ret);
    return 0;
}*/
