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

    addr += ctx->bias;
    debug("core_read: %zd bytes from %lx", len, addr);

    for (m = ctx->maps; m != NULL; m = m->next)
    {
        if (addr >= m->vaddr && addr+len <= m->vaddr+m->len)
        {
            break;
        }
    }
    if (m == NULL)
    {
        debug("core_read: 0x%lx: segment not available", addr);
        return NULL;
    }

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
        w = stack[elems];           \
        elems++;                    \
    } while (0)
#define TOP (elems-1)

unsigned char* evaluate_loc_expr(Dwarf_Op *expr, size_t exprlen,
                                 struct expr_context *ctx, size_t data_len)
{
    int ret;
    unsigned i, elems = 0;
    Dwarf_Word stack[STACKSIZE];
    Dwarf_Word location;
    unw_word_t w;

    debug("evaluating DWARF expression:");
    for (i = 0; i < exprlen; i++)
    {
        Dwarf_Op *o = expr + i;
        debug("\t%x (%lx %lx)", o->atom, o->number, o->number2);
    }

    for (i = 0; i < exprlen; i++)
    {
        Dwarf_Op *o = expr + i;

        switch (o->atom)
        {
        case DW_OP_fbreg:
            /* TODO: we should evaluate DW_AT_frame_base which is almost
             *       always DW_OP_call_frame_cfa */
            fail_if(ctx->cfa == 0, "ctx->cfa");
            PUSH(ctx->cfa + o->number);
            break;
        case DW_OP_addr:
        case DW_OP_const8u:
            PUSH(o->number);
            break;
        case DW_OP_GNU_push_tls_address:
            warn("unknown opcode %x (not fatal)", o->atom);
            return NULL;
        default:
            /* TODO: implement the rest */
            fail("unknown opcode %x", o->atom);
            return NULL;
            break;
        }
    }

    /* returns null if stack is empty */
    POP(location);

    unsigned char *val = core_read(ctx, location, data_len);
    if (val == NULL)
        return NULL;

    return val;
}
