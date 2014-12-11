/*
 * Copyright (c) 2014, Joshua Wright <jwright@willhackforsushi.com>
 *
 * $Id: $
 *
 * See the LICENSE file for license details.
 *
 */

/* Prototypes */
void lamont_hdump(uint8_t *bp, unsigned int length);
char *printmac(unsigned char *mac);
int IsBlank(char *s);


#define __swab16(x) \
({ \
        uint16_t __x = (x); \
        ((uint16_t)( \
                (((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
                (((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#ifdef WORDS_BIGENDIAN
#warning "Compiling for big-endian"
#define le16_to_cpu(x) __swab16(x)
#else
#define le16_to_cpu(x) (x)
#endif
