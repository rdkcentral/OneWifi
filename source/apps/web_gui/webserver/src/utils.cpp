/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils.h"
#include "base64.h"
#include "wifi_util.h"

const char *utils_t::get_png_chunk_type(png_chunk_type_t type)
{
    const char *str;
    
    switch (type) {
        case png_chunk_type_header:
            str = "header";
            break;
        case png_chunk_type_plte:
            str = "palette";
            break;
        case png_chunk_type_data:
            str = "data";
            break;
        case png_chunk_type_footer:
            str = "footer";
            break;
        case pmg_chunk_type_srgb:
            str = "srgb";
            break;
        case png_chunk_type_exif:
            str = "exif";
            break;
        default:
            str = "unknown";
    }
    
    return str;
}

int utils_t::analyze_png_buffer(png_file_info_t *info)
{
    png_signature_t signature = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
    png_signature_t *sig;
    size_t len = 0;
    
    info->num_chunks = 0;
    sig = (png_signature_t *)info->dec_info.ptr;
    if (memcmp((unsigned char *)sig, &signature, sizeof(png_signature_t)) != 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Signature mismatch\n", __func__, __LINE__);
        print_hex_dump(sizeof(png_signature_t), (unsigned char *)sig);
        return -1;
    }
    
    len += sizeof(png_signature_t);
    info->chunks[info->num_chunks] = (png_chunk_t *)(info->dec_info.ptr + len);
    
    while (len < info->dec_info.len) {
        
        len += (htonl(info->chunks[info->num_chunks]->len) + sizeof(png_chunk_t));
        info->num_chunks++;
        info->chunks[info->num_chunks] = (png_chunk_t *)(info->dec_info.ptr + len);
    }
    
    return 0;
}

int utils_t::png_concatenate(png_file_info_t info[], unsigned int num, unsigned char **out)
{
    unsigned int i, j, total_len = 0, chunk_size = 0;
    png_signature_t signature = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
    unsigned int start_pos, end_pos;
    unsigned char *ptr = NULL;
    //png_chunk_hdr_t *final_hdr, *hdr;
    
    for (i = 0; i < num; i++) {
        info[i].dec_info.ptr = base64_decode((const char *)info[i].enc_info.ptr, info[i].enc_info.len, &info[i].dec_info.len);
        analyze_png_buffer(&info[i]);
    }
    
    ptr = (unsigned char *)malloc(MAX_PNG_FILE_SZ);
   
    memcpy(ptr + total_len, &signature, sizeof(png_signature_t));
    total_len += sizeof(png_signature_t);
    
    //final_hdr = (png_chunk_hdr_t *)(((png_chunk_t *)(ptr + total_len))->data);
    
    //printf("%s:%d: Width: %d\tHeight: %d\n", __func__, __LINE__, htonl(final_hdr->width), htonl(final_hdr->height));
    for (i = 0; i < num; i++) {
        if (i == 0) {
            start_pos = 0;
            end_pos = info[i].num_chunks - 1;
        } else if (i == (num - 1)) {
            start_pos = 3;
            end_pos = info[i].num_chunks;
            //hdr = (png_chunk_hdr_t *)info[i].chunks[0]->data;
            //final_hdr->height += hdr->height;
            
        } else {
            start_pos = 3;
            end_pos = info[i].num_chunks - 1;
            //hdr = (png_chunk_hdr_t *)info[i].chunks[0]->data;
            //final_hdr->height += hdr->height;
            
        }
        
        for (j = start_pos; j < end_pos; j++) {
            chunk_size = sizeof(png_chunk_t) + htonl(info[i].chunks[j]->len);
            //printf("%s:%d: File[%d]\tChunk Index[%d]\tType: %s\tSize to copy: %u\n", __func__, __LINE__, i, j,
                   //get_png_chunk_type((png_chunk_type_t)htonl(info[i].chunks[j]->type)), chunk_size);
            memcpy(ptr + total_len, (unsigned char *)info[i].chunks[j], chunk_size);
            total_len += chunk_size;
        }
        
        free(info[i].dec_info.ptr);
    }
    
    //printf("%s:%d: Final Height: %d\n", __func__, __LINE__, htonl(final_hdr->height));
    
    *out = ptr;
    return total_len;
}

void utils_t::print_hex_dump(unsigned int length, uint8_t *buffer)
{
    unsigned int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

utils_t::utils_t()
{
    
}

utils_t::~utils_t()
{
    
}
