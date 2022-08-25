#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define  ANSC_BASE64_CODES      \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#define ANSC_BASE64_DECODE_OVERRUN_SIZE             3


/**********************************************************************

    caller:     owner of this object

    prototype:

        unsigned char*
        AnscBase64DecodeLine
            (
                const unsigned char*                pString,
                unsigned char*                      pData,
                unsigned long*                      pulSize
            )

    description:

        This function is called to decode a line of
        Base64 encode message to original text. Users
        should not call this function directly. Instead
        users should call AnscBase64Decode.

    argument:   const unsigned char*                pString
                Buffer to Base64 encoded message.

                unsigned char*                      pData
                Buffer to decoded text.

                unsigned long*                      pulSize [OUT]
                It contains the length of decoded text after
                this functions successfully returns.

    return:     Buffer that contains decoded text, no need
                to be free.

**********************************************************************/

unsigned char*
AnscBase64DecodeLine
    (
        const unsigned char*                pString,
        unsigned char*                      pData,
        unsigned long*                      pulSize
    )
{
    unsigned long                           ulSize  = 0;
    int                             length  = ((pulSize == NULL) ? 0 : (*pulSize)); /*RDKB-6183, CID-24152, null check before use*/

    if (pString)
    {
        /* do a format verification first */
        if (length > 0)
        {
            int                     count   = 0, rem = 0;
            const char*             tmp     = (char *)pString;

            while (length > 0)
            {
                int                 skip;

                skip    = strspn(tmp, (const char*)ANSC_BASE64_CODES);
                count   += skip;
                length  -= skip;
                tmp     += skip;

                if (length > 0)
                {
                    int             i, vrfy;

                    vrfy    = strcspn(tmp, (const char*)ANSC_BASE64_CODES);

                    for (i = 0; i < vrfy; i++)
                    {
                        if (tmp[i] == ' ' || tmp[i] == 0x0D || tmp[i] == 0x0A)
                        {
                            continue;
                        }

                        if (tmp[i] == '=')
                        {
                            /* we should check if we're close to the end of the string */
                            rem = count % 4;

                            /* rem must be either 2 or 3, otherwise no '=' should be here */
                            if (rem < 2)
                            {
                                return NULL;
                            }

                            /* end-of-message recognized */
                            goto NEXT;
                        }
                        else
                        {
                            /* Transmission error; RFC tells us to ignore this, but:
                             *  - the rest of the message is going to even more corrupt since we're sliding bits out of place
                             * If a message is corrupt, it should be dropped. Period.
                             */

                            return NULL;
                        }
                    }

                    length -= vrfy;
                    tmp += vrfy;
                }
            }


NEXT:

            ulSize  = (count / 4) * 3 + (rem ? (rem - 1) : 0) + ANSC_BASE64_DECODE_OVERRUN_SIZE;

            if (count > 0)
            {
                int                 i, qw = 0, tw = 0;

                tmp     = (char *)pString;
                length  = ((pulSize == NULL) ? 0 : (*pulSize)); /*RDKB-6183, CID-24152, null check before use*/

                for (i = 0; i < length; i++)
                {
                    char        ch = pString[i];
                    unsigned char       bits;

                    if (ch == ' ' || ch == 0x0D || ch == 0x0A)
                    {
                        continue;
                    }

                    bits = 0;
                    if ((ch >= 'A') && (ch <= 'Z'))
                    {
                        bits = (unsigned char) (ch - 'A');
                    }
                    else if ((ch >= 'a') && (ch <= 'z'))
                    {
                        bits = (unsigned char) (ch - 'a' + 26);
                    }
                    else if ((ch >= '0') && (ch <= '9'))
                    {
                        bits = (unsigned char) (ch - '0' + 52);
                    }
                    else if (ch == '+')
                    {
                        bits = (unsigned char)62;
                    }
                    else if (ch == '/')
                    {
                        bits = (unsigned char)63;
                    }
                    else if (ch == '=')
                    {
                        break;
                    }

                    switch (qw++)
                    {
                        case    0:

                                pData[tw+0] = (bits << 2)   & 0xFC;

                                break;

                        case    1:

                                pData[tw+0] |= (bits >> 4)  & 0x03;
                                pData[tw+1] = (bits << 4)   & 0xF0;

                                break;

                        case    2:

                                pData[tw+1] |= (bits >> 2)  & 0x0F;
                                pData[tw+2] = (bits << 6)   & 0xC0;

                                break;

                        case    3:

                                pData[tw+2] |= bits         & 0x3F;

                                break;
                    }

                    if (qw == 4)
                    {
                        qw = 0;
                        tw += 3;
                    }
                }
            }
        }
    }

    if (pulSize)
    {
        *pulSize    = ulSize - ANSC_BASE64_DECODE_OVERRUN_SIZE;
    }

    return pData;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        unsigned char*
        AnscBase64Decode
            (
                unsigned char*                      pEncode,
                unsigned long*                      pulSize
            );

    description:

        This function is called to decode Base64 encode
        message to original text.

    argument:   unsigned char*                      pEncode
                Buffer to Base64 encoded message.

                unsigned long*                      pulSize [OUT]
                It contains the length of decoded text after
                this functions successfully returns.

    return:     Buffer that contains decoded text, needs to
                be free after use.

**********************************************************************/

unsigned char*
AnscBase64Decode
    (
        unsigned char*                      pEncode,
        unsigned long*                      pulSize
    )
{
    unsigned char*                          pDecode;
    unsigned char*                          pBuf;
    unsigned long                           ulEncodedSize;

    pBuf            = pEncode;

    /* allocate big enough memory to avoid memory reallocation */
    ulEncodedSize   = strlen((const char*)pEncode);
    pDecode         = calloc(0, ulEncodedSize);

    if( AnscBase64DecodeLine(pBuf, pDecode, &ulEncodedSize) == NULL)
    {
        //AnscTrace("Failed to decode the Base64 data.\n");

        free(pDecode);

        return NULL;
    }

    if (pulSize)
    {
        *pulSize    = ulEncodedSize;
    }

    return pDecode;
}

unsigned long AnscSizeOfString(char* s)
{
    return (unsigned long)(strlen(s));
}

void AnscCopyString(char*  destination, char*  source)
{
    if ( !source )
    {
        destination[0] = 0;
    }
    else
    {
        strcpy(destination, source);
    }
}
