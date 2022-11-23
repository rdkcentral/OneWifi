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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "pack_file.h"

struct pack_hdr *pack_files(char *files[], uint32_t nfile)
{
    struct pack_hdr *pkthdr;
    struct file_hdr *filhdr;
    uint32_t i;
    off_t hdr_size;
    struct stat buf;
    FILE *fp;

    if (!files) {
        fprintf(stderr, "%s: bad parameter\n", __FUNCTION__);
        return NULL;
    }

    hdr_size = sizeof(struct pack_hdr) + nfile * sizeof(struct file_hdr);
    if ((pkthdr = malloc(hdr_size)) == NULL) {
        fprintf(stderr, "%s: no memory\n", __FUNCTION__);
        return NULL;
    }

    pkthdr->version = PACK_VERION;
    pkthdr->nfile   = nfile;
    pkthdr->totsize = hdr_size;

    for (i = 0; i < nfile; i++) {
        filhdr = &pkthdr->files[i];
        snprintf(filhdr->path, sizeof(filhdr->path), "%s", files[i]);
        filhdr->offset = pkthdr->totsize;

        /* CID: 135476 Time of check time of use*/
        if ((fp = fopen(files[i], "rb")) == NULL) {
            fprintf(stderr, "%s: cannot open file %s\n", __FUNCTION__, files[i]);
            free(pkthdr);
            return NULL;
        }
        // TODO: add file lock to prevent file changed during packaging
        if (fstat(fileno(fp), &buf) != 0) {
            fprintf(stderr, "%s: fstat() error\n", __FUNCTION__);
            free(pkthdr);
            return NULL;
        }
        filhdr->size = buf.st_size;
        pkthdr->totsize += filhdr->size;

        if ((pkthdr = realloc(pkthdr, pkthdr->totsize)) == NULL) {
            fprintf(stderr, "%s: no memory\n", __FUNCTION__);
            return NULL;
        }

        if (fread((char *)pkthdr + filhdr->offset, filhdr->size, 1, fp) != 1) {
            fprintf(stderr, "%s: fread error for %s\n", __FUNCTION__, files[i]);
            fclose(fp);
            free(pkthdr);
            return NULL;
        }

        fclose(fp);
    }

    memset(pkthdr->chksum, 0, sizeof(pkthdr->chksum)); // TODO:

    return pkthdr;
}

int unpack_files(const struct pack_hdr *pkthdr)
{
    FILE *fp;
    const struct file_hdr *filhdr;
    off_t hdr_size;
    int i;

    if (!pkthdr) {
        fprintf(stderr, "%s: bad parameter\n", __FUNCTION__);
        return -1;
    }

    hdr_size = sizeof(struct pack_hdr) + pkthdr->nfile * sizeof(struct file_hdr);
    if (pkthdr->version != PACK_VERION || pkthdr->totsize < hdr_size) {
        fprintf(stderr, "%s: version not match or bad format\n", __FUNCTION__);
        return -1;
    }

    // TODO: chksum

    for (i = 0; i < pkthdr->nfile; i++) {
        filhdr = &pkthdr->files[i];

        if (filhdr->offset < hdr_size) {
            fprintf(stderr, "%s: invalid offset for %s\n", __FUNCTION__, filhdr->path);
            return -1;
        }

        // XXX: support mkdir for nonexist dir ?

        if ((fp = fopen(filhdr->path, "wb")) == NULL) {
            fprintf(stderr, "%s: fail to open file %s\n", __FUNCTION__, filhdr->path);
            return -1;
        }

        if (fwrite((char *)pkthdr + filhdr->offset, filhdr->size, 1, fp) != 1) {
            fprintf(stderr, "%s: fwrite error for %s\n", __FUNCTION__, filhdr->path);
            fclose(fp);
            return -1;
        }

        fclose(fp);
    }

    return 0;
}

void dump_pack_hdr(const struct pack_hdr *pkthdr)
{
    const struct file_hdr *filhdr;
    unsigned int i;

    if (!pkthdr)
        return;

    fprintf(stderr, "Version     : %u\n", pkthdr->version);
    fprintf(stderr, "Num of Files: %u\n", pkthdr->nfile);
    fprintf(stderr, "Checksum    : ");
    for (i = 0; i < sizeof(pkthdr->chksum); i++)
        fprintf(stderr, "%02X", pkthdr->chksum[i]);
    fprintf(stderr, "\n");

    for (i = 0; i < pkthdr->nfile; i++) {
        filhdr = &pkthdr->files[i];
        fprintf(stderr, "  [%d] Path  : %s\n", i, filhdr->path);
        fprintf(stderr, "  [%d] Offset: %lu\n", i, filhdr->offset);
        fprintf(stderr, "  [%d] Size  : %lu\n", i, filhdr->size);
    }

    return;
}

