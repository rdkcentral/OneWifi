/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef _PACK_FILE_H_
#define _PACK_FILE_H_

#define PACK_VERION     1

struct file_hdr {
    char        path[256];
    off_t       offset;     /* from first byte of packet header */
    off_t       size;       /* file size */
};

struct pack_hdr {
    uint8_t     version;
    uint8_t     nfile;
    off_t       totsize;    /* whole package size in byte */
    uint8_t     chksum[16]; /* we can use md5-128 bits */
    struct file_hdr files[0];
};

struct pack_hdr *pack_files(char *files[], uint32_t nfile);
int unpack_files(const struct pack_hdr *pkthdr);
void dump_pack_hdr(const struct pack_hdr *pkthdr);

#endif
