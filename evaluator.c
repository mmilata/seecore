#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include "seecore.h"

static unsigned char* core_read(struct expr_context *ctx, Dwarf_Addr addr,
                                size_t len)
{
    struct data_map *m;
    off_t file_off, seek_res;
    ssize_t read_res;

    for (m = ctx->maps; m != NULL; m = m->next)
    {
        if (addr >= m->vaddr && addr+len <= m->vaddr+m->len)
        {
            break;
        }
    }
    fail_if(m == NULL, "core_read wrong address");

    file_off = m->off + (addr - m->vaddr);

    seek_res = lseek(ctx->core_fd, file_off, SEEK_SET);
    fail_if(seek_res != file_off, "lseek");

    unsigned char *result = xalloc(len);
    read_res = read(ctx->core_fd, result, len);
    fail_if(read_res < 0 || (size_t)read_res < len, "read");

    return result;
}

#define STACKSIZE 128
#define PUSH(w)                     \
    do {                            \
        if (elems == STACKSIZE)     \
        {                           \
            warn("stack overflow"); \
            return NULL;            \
        }                           \
        stack[elems] = (w);         \
        elems++;                    \
    } while (0)
#define POP(w)                      \
    do {                            \
        if (elems == 0)             \
        {                           \
            warn("stack underrun"); \
            return NULL;            \
        }                           \
        elems--;                    \
        w = stack[elems]            \
        elems++;                    \
    } while (0)
#define TOP (elems-1)

unsigned char* evaluate_loc_expr(Dwarf_Op *expr, size_t exprlen,
                                 struct expr_context *ctx, size_t data_len)
{
    int ret;
    unsigned i, elems = 0;
    Dwarf_Word stack[STACKSIZE];
    unw_word_t w;

    printf("\t\t\tCFA: %lx\n", ctx->cfa);
    printf("\t\t\t");

    for (i = 0; i < exprlen; i++)
    {
        Dwarf_Op *o = expr + i;
        printf("%hx (%ld %ld) ", o->atom, o->number, o->number2);

        switch (o->atom)
        {
        case DW_OP_fbreg:
            /* TODO: we should evaluate DW_AT_frame_base which is almost
             *       always DW_OP_call_frame_cfa */
            fail_if(ctx->cfa == 0, "ctx->cfa");
            PUSH(ctx->cfa + o->number);
            //printf("%lx", stack[TOP]);
            break;
        default:
            fail("unknown opcode %x", o->atom);
            break;
        }
    }
    printf("\n");

    if (elems == 0)
        return NULL;

    unsigned char *val = core_read(ctx, stack[TOP], data_len);
    printf("\t\t\tresult: ");
    for (i = 0; i < data_len; i++)
    {
        printf("%02hhx", val[data_len-1-i]);
    }
    printf("\n");

    return val;
}
