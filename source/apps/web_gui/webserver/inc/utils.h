/*
 ** If not stated otherwise in this file or this component's Licenses.txt file the
 ** following copyright and licenses apply:
 **
 ** Copyright 2018 RDK Management
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 ** http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 **/

#ifndef _UTILS_H_
#define _UTILS_H_

#include <cstdint>

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_PNG_CHUNKS  12
#define MAX_PNG_FILE_SZ 1024*1024

typedef enum {
    png_chunk_type_header = 0x49484452,
    png_chunk_type_plte = 0x504c5445,
    png_chunk_type_data = 0x49444154,
    png_chunk_type_footer = 0x49454e44,
    pmg_chunk_type_srgb = 0x73524742,
    png_chunk_type_exif = 0x65584966,
} png_chunk_type_t;

typedef unsigned char   png_signature_t[8];
typedef unsigned int    png_crc_t;

typedef struct {
    unsigned char *ptr;
    size_t len;
} png_buffer_info_t;

typedef struct {
    unsigned int len;
    unsigned int type;
    unsigned char   data[0];
    unsigned int    crc;
} png_chunk_t;

typedef struct {
    unsigned int width;
    unsigned int height;
    unsigned char   bd;
    unsigned char ct;
    unsigned char cm;
    unsigned char fm;
    unsigned char im;
} png_chunk_hdr_t;

typedef struct {
    png_buffer_info_t enc_info;
    png_buffer_info_t dec_info;
    unsigned int num_chunks;
    png_chunk_t *chunks[MAX_PNG_CHUNKS];
} png_file_info_t;

class utils_t {

public:
	static void print_hex_dump(unsigned int length, uint8_t *buffer);
    static int png_concatenate(png_file_info_t info[], unsigned int num, unsigned char **out);
    static int analyze_png_buffer(png_file_info_t *info);
    static const char *get_png_chunk_type(png_chunk_type_t type);
    
public:
	utils_t();
	~utils_t();
};

#ifdef __cplusplus
}
#endif

#endif // _UTILS_H_
