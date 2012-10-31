/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "seecore.h"

int main(int argc, char *argv[])
{
    /* TODO: investigate DW_TAG_GNU_call_site:
     * http://gcc.gnu.org/wiki/summit2010?action=AttachFile&do=get&target=jelinek.pdf
     * http://gcc.gnu.org/ml/gcc-patches/2010-08/txt00153.txt */
    /* TODO: decompose structs into members   */
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <binary> <core>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    seecore_message_level = 2;

    struct core_contents *c = analyze_core(argv[1], argv[2]);
    print_core(c);
    free_core(c);

    return EXIT_SUCCESS;
}
