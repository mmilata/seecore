/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "seecore.h"

static void print_usage_and_die(char **argv)
{
    fprintf(stderr, "usage: %s [-v] [-v] [-v] <binary> <core>\n", argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "v")) != -1)
    {
        switch (opt)
        {
        case 'v':
            seecore_message_level++;
            break;
        default:
            print_usage_and_die(argv);
            break;
        }
    }

    /* need exactly two positional arguments */
    if (argc - optind != 2)
    {
        print_usage_and_die(argv);
    }

    /* extract contents of the core */
    struct core_contents *c = analyze_core(argv[optind], argv[optind+1]);

    /* print it */
    print_core(c);

    /* free all dynamically allocated memory */
    free_core(c);

    return EXIT_SUCCESS;
}
