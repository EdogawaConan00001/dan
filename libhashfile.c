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
int MIN (int a, int b){
    if(a<b)return a;
    else return b;
}
int split_line(struct hashfile_handle *handle, char *buffer){
    /*go to the beginning of the nextline*/
    int ret = 0;
    int i;
    int len = strlen(buffer);
    for(i = 0; i < len; i++){
        if(buffer[i] == '\r' && buffer[i+1] == '\n'){
            ret = lseek(handle->fd, (off_t)-len+i+2, SEEK_CUR);
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
        if(buffer[i] == '\r' && buffer[i+1] == '\n'){
           ret = lseek(handle->fd, (off_t)-len+i+2, SEEK_CUR);    
           break;
        }
        value[i] = buffer[i];
        //ret = split_line(handle, buffer);
    }
    return ret;
}
int get_int_value(struct hashfile_handle *handle, int *value){
    int ret;
    char buffer[MAX_B] = "";
    ret = read(handle->fd, buffer, sizeof(buffer));
    /*if(strlen(buffer) < sizeof(buffer)){
        printf("read bytes:%d\nbuffer: %s\n", (int)strlen(buffer), buffer); 
        printf("Will end of file\n");
    }*/
    *value = (int)strtol(buffer, NULL, 10);
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
        //printf("buffer_part %s\n", buffer);
        int len = strlen(buffer);
        if(ret == 0){
            printf("end of file\n");
            break;
        }
        int i;
        for(i = 0; i < len; i++){
            if(i == 0){
                if(flag_r == 1 && buffer[i] == '\n' && buffer[i+1] == '\r'
                        && buffer[i+2] == '\n'){
                    flag_r = 0;
                    ret = lseek(handle->fd, (off_t)-len+3, SEEK_CUR);
                    //printf("====r+nrn\n");
                    end = 1;
                    break;
                }else if(flag_rn == 1 && buffer[i] == '\r' && buffer[i+1] == '\n'){
                    flag_rn = 0;
                    ret = lseek(handle->fd, (off_t)-len+2, SEEK_CUR);
                    //printf("====rn+rn\n");
		    end = 1;
                    break;
                }else if(flag_rnr = 1 && buffer[i] == '\n'){
                    flag_rnr = 0;
                    ret = lseek(handle->fd, (off_t)-len+1, SEEK_CUR);
                    //printf("====rnr+n\n");
                    end = 1;
                    break;
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
        printf("END OF FILE\n");
        return 0;
    }else{
        ret = lseek(handle->fd, (off_t)-11, SEEK_CUR);
    }
    
    ret = get_key_value(handle, handle->current_file.dir_name, 
            sizeof(handle->current_file.dir_name), &handle->current_file.dir_length);
    ret = get_key_value(handle, handle->current_file.file_name, 
            sizeof(handle->current_file.file_name), &handle->current_file.file_length);
    ret = get_key_value(handle, handle->current_file.extensions, sizeof(handle->current_file.extensions), &handle->current_file.ext_value);
    ret = get_int_value(handle, &handle->current_file.namespace_depth);
    ret = get_int_value(handle, &handle->current_file.file_size);
    ret = get_char_value(handle, handle->current_file.attr_flags);
    ret = get_int_value(handle, &handle->current_file.file_id);
    ret = get_int_value(handle, &handle->current_file.hardlinks);
    ret = get_char_value(handle, handle->current_file.reparse_flags);
    ret = get_int_value(handle, &handle->current_file.ctime);
    ret = get_int_value(handle, &handle->current_file.atime);
    //printf("ret_file1 %d\n", ret);
    ret = get_int_value(handle, &handle->current_file.mtime);
    //printf("ret_file2 %d\n", ret);
    //ret = lseek(handle->fd, 0, SEEK_CUR);
    //ret = Cur_part_end(handle);
    //printf("file end ret:%d\n", ret);
    return ret;
}

uint64_t hashfile_curfile_size(struct hashfile_handle *handle){
    return handle->current_file.file_size;
}
int chunk_hash_size(struct chunk_info){
    return (int)strlen(chunk_info.hash);
}
const struct chunk_info *hashfile_next_chunk(struct hashfile_handle *handle){
    int ret;
    if(!hashfile_curfile_size(handle)){/* file_size == 0*/
        ret = Cur_part_end(handle);
        return NULL;
    }
    char buffer[MAX_B] = "";
    while(1){
        ret = read(handle->fd, buffer, sizeof(buffer));
        if(buffer[0] == 'S' || buffer[0] == 'V' || buffer[0] == 'A'){
            ret = split_line(handle, buffer);
            continue;
        }else{
            ret = lseek(handke->fd, (off_t)-strlen(buffer), SEEK_CUR);
            int hash_size = 10;
            if(buffer[0] == 'z'){
                hash_size = 12;
            }
            ret = get_key_value(handle, handle->current_chunk_info.hash, hash_size, 
                    &handle->current_chunk_info.size);
            break;
        }
    }
    return &handle->current_chunk_info;
}

int read_hashfile(char **hashfile_name, int count){
    struct hashfile_handle *handle;
    int ret;
    int hashfile_count = 0;
    for(; hashfile_count < count; hashfile_count++){
        handle = hashfile_open(hashfile_name[hashfile_count]);
	int file_count = 0;
        //ret = lseek(handle->fd, 54852861, SEEK_SET);//2978
        
        //ret = hashfile_next_file(handle);
	//printf("file id:%d\ndir_name:%s dir_length:%d\nfile_name %s file_length %d\n", file_count, handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_length);
        //printf("ret %d\n", ret);
        //ret = hashfile_next_file(handle);
        while(1){
            ret = hashfile_next_file(handle);
            //printf("reading file ret%d\n", ret);
            if(ret == 0)
            {
                printf("file counts: %d\n", file_count);
                break;
            }
            //printf("file id:%d\ndir_name:%s dir_length:%d\nfile_name %s file_length %d\n", file_count, handle->current_file.dir_name, handle->current_file.dir_length, handle->current_file.file_name, handle->current_file.file_length);
            //printf("ret %d\n", ret);
            
            file_count++;
        }
    }
    return ret;
}
int main(int argc, char *argv[]){
    int ret = read_hashfile(&argv[1], argc-1);
    printf("ret1 %d\n", ret);
    return 0;
}
