/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */

#ifndef SEECORE_INTERNAL_H
#define SEECORE_INTERNAL_H

#include <libunwind-coredump.h>
#include <elfutils/libdwfl.h>

#include "seecore.h"

struct expr_context
{
    unw_cursor_t *curs;
    int core_fd;
    struct data_map *maps;
    Dwarf_Addr ip;
    Dwarf_Addr cfa;
    Dwarf_Addr bias;
};

/* maps executable segments to their backing files - needed by libunwind */
struct exec_map
{
    uint64_t         vaddr;
    char*            file;
    struct exec_map* next;
};

/* item itself can be a list, i.e. the macro also does concatenation */
/* TODO: reconsider and eventually remove this ^ capability */
#define list_append(head,tail,item)          \
    do{                                      \
        void *_tmp = (item);                 \
        if (_tmp == NULL)                    \
            break;                           \
        if ((head) == NULL)                  \
        {                                    \
            (head) = (tail) = _tmp;          \
        }                                    \
        else                                 \
        {                                    \
            (tail)->next = _tmp;             \
        }                                    \
        while ((tail)->next)                 \
            (tail) = (tail)->next;           \
    } while(0)

/* util.c */
void fail(const char *fmt, ...);
void fail_if(int p, const char *fmt, ...);
char* xsprintf(const char *fmt, ...);
char* xstrdup(const char *s);
void* xalloc(size_t size);

extern int message_level;
void message(int level, const char *fmt, ...);

/* evaluator.c */
unsigned char* evaluate_loc_expr(Dwarf_Op *expr, size_t expr_len,
                                 struct expr_context *ctx, size_t data_len);

/* variable.c */
void analyze_name_location(Dwarf_Die *die, Dwarf_Files *files, char **name,
                           struct location* loc);
struct variable* child_variables(Dwarf_Die *parent, Dwarf_Files *files,
                                 struct expr_context *ctx, bool params);
void free_variables(struct variable *v);

/* stack.c */
bool supported_language(Dwarf_Die *cu);
struct thread* unwind_stacks(Dwfl *dwfl, const char *core_file,
                             struct exec_map *em,
                             struct expr_context *ctx);

#define warn(...)  message(1, __VA_ARGS__)
#define info(...)  message(2, __VA_ARGS__)
#define debug(...) message(3, __VA_ARGS__)


#endif /* SEECORE_INTERNAL_H */
