/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <elfutils/libdwfl.h>
#include <dwarf.h>
#include <libunwind-coredump.h>

#include "seecore-internal.h"

bool supported_language(Dwarf_Die *cu)
{
    int ret;
    Dwarf_Word lang;
    Dwarf_Attribute at;

    if (dwarf_attr(cu, DW_AT_language, &at) == NULL)
    {
        warn("CU %s: unknown language", dwarf_diename(cu));
        return false;
    }

    ret = dwarf_formudata(&at, &lang);
    fail_if(ret == -1, "dwarf_formudata");

    switch (lang)
    {
    case DW_LANG_C89:
    case DW_LANG_C:
    case DW_LANG_C99:
        /* good! */
        break;
    case DW_LANG_C_plus_plus:
        warn("CU %s: C++ not supported", dwarf_diename(cu));
        return false;
        break;
    default:
        debug("CU %s: unsupported language: 0x%lx",
             dwarf_diename(cu), (unsigned long)lang);
        return false;
        break;
    }

    return true;
}

/* Note that the function:
 *  - updates scopes and nscopes if the currently analyzed scopes corresponded
 *    to an inline function
 *  - frees scopes if currently analyzed scope was not-inlined function
 */
static struct frame* analyze_scopes(Dwarf_Die **scopes, int *nscopes,
                             struct expr_context *ctx,
                             Dwarf_Files *files, bool skip_first)
{
    int i;
    Dwarf_Die *scope_die;

    if (*nscopes == -1)
    {
        warn("\t\tfailed to get scopes");
        return NULL;
    }
    else if (*nscopes == 0)
    {
        debug("\t\tno scopes");
        return NULL;
    }
    else if (*nscopes > 0)
    {
        debug("\t\tscopes:");
        for (i = 0; i < *nscopes; i++)
        {
            debug("\t\t\ttag: 0x%x\toffset: %lx", dwarf_tag(&(*scopes)[i]),
                  dwarf_dieoffset(&(*scopes)[i]));
        }
    }

    int tag;
    bool boundary = false;
    struct frame *frame = xalloc(sizeof(*frame));

    /* iterate and extract variable until we reach function boundary */
    i = (skip_first ? 1 : 0);
    for (; i < *nscopes; i++)
    {
        scope_die = &(*scopes)[i];

        list_append(frame->vars, frame->vars_tail,
                    child_variables(scope_die, files, ctx, false));

        tag = dwarf_tag(scope_die);
        boundary = (tag == DW_TAG_subprogram
                 || tag == DW_TAG_inlined_subroutine);
        if (boundary)
        {
            /* get function parameters */
            list_append(frame->params, frame->params_tail,
                        child_variables(scope_die, files, ctx, true));

            /* add function name to frame struct */
            analyze_name_location(scope_die, files,
                                  &frame->name, &frame->loc);
            info("\t\tfunction name: %s", frame->name);
            break;
        }
    }

    fail_if(!boundary, "missing function boundary");

    /* we have to make a copy of the *scope_die as the pointer points inside
     * scopes[] which we want to free */
    Dwarf_Die tmp = *scope_die;
    free(*scopes);

    /* if this function is not inlined, do not update the scopes array as we
     * don't want to continue further */
    if (tag == DW_TAG_subprogram)
    {
        *nscopes = 0;
        return frame;
    }

    /* otherwise, get scopes for the inlined function, i.e. function into which
     * it was inlined */
    *nscopes = dwarf_getscopes_die(&tmp, scopes);
    return frame;
}

static struct frame* unwind_thread(Dwfl *dwfl, unw_addr_space_t as,
                                   struct UCD_info *ui, int thread_no,
                                   struct expr_context *ctx)
{
    info("thread %d:", thread_no);

    int i, ret;
    unw_cursor_t c, c_cfa;

    _UCD_select_thread(ui, thread_no);

    ret = unw_init_remote(&c, as, ui);
    fail_if(ret < 0, "unw_init_remote");

    ret = unw_init_remote(&c_cfa, as, ui);
    fail_if(ret < 0, "unw_init_remote");

    struct frame *head = NULL, *tail = NULL;

    /* infinite loop insurance */
    int count = 1000;
    while (--count > 0)
    {
        unw_word_t ip;
        ret = unw_get_reg(&c, UNW_REG_IP, &ip);
        fail_if(ret < 0, "unw_get_reg");

        if (ip == 0)
            break;

        unw_word_t off;
        char funcname[10*1024];
        funcname[0] = '\0';
        ret = unw_get_proc_name(&c, funcname, sizeof(funcname)-1, &off);
        if (ret < 0)
        {
            warn("unw_get_proc_name failed for IP %lx", (unsigned long)ip);
        }
        info("\t%llx %s", (unsigned long long)ip, funcname);

        /* According to spec[1], CFA is RSP of the previous frame. However,
         * libunwind returns CFA = RSP of the current frame. So we need to keep
         * track of the previous (i.e. next to be unwound) frame.
         *
         * [1] System V Application Binary Interface AMD64 Architecture
         *     Processor Supplement
         *     http://www.x86-64.org/documentation/abi.pdf
         */
        ctx->cfa = 0;
        ret = unw_step(&c_cfa);
        if (ret > 0)
        {
            unw_word_t cfa;
            ret = unw_get_reg(&c_cfa, UNW_X86_64_CFA, &cfa);
            if (ret == 0)
            {
                ctx->cfa = (Dwarf_Addr)cfa;
            }
        }

        /* find compilation unit owning the IP */
        Dwarf_Die *cu = dwfl_addrdie(dwfl, (Dwarf_Addr)ip, &(ctx->bias));
        if (!cu)
        {
            warn("\t\tcannot find CU for ip %lx", (unsigned long)ip);
            goto synth_frame;
        }

        if (!supported_language(cu))
        {
            warn("\t\tunsupported CU language");
            goto synth_frame;
        }

        /* needed by child_variables */
        Dwarf_Files *files;
        ret = dwarf_getsrcfiles(cu, &files, NULL);
        fail_if(ret == -1, "dwarf_getsrcfiles");

        /* dwarf expression evaluation needs register values */
        ctx->curs = &c;
        ctx->ip = (Dwarf_Addr)ip; /* TODO: subtract 1 as this is return address? */

        /* TODO: we have CU - fall back to CU name if subprogram not found */

        /* Following code deals with inlined functions, which do not have their
         * own stack frame. It is somewhat ugly due to two constraints:
         *  - we want to produce at least one frame even if analyze_scopes
         *    fails
         *  - we may want to further process the frame that is returned the
         *    last, i.e. the one that belongs to the non-inlined function
         */
        Dwarf_Die *scopes;
        int nscopes = dwarf_getscopes(cu, (Dwarf_Addr)ip, &scopes);
        struct frame *frame = analyze_scopes(&scopes, &nscopes, ctx, files, false);

        if (frame == NULL)
        {
            goto synth_frame;
        }

        struct frame *last_frame;
        while (frame)
        {
            list_append(head, tail, frame);
            last_frame = frame;
            frame = analyze_scopes(&scopes, &nscopes, ctx, files, true);
        }
        frame = last_frame;
        /* frame->ip = (uint64_t)ip; */

        goto next;

synth_frame:
        /* synthesize frame even though we have no other information except
         * that it's there */
        frame = xalloc(sizeof(*frame));
        list_append(head, tail, frame);
        /* frame->ip = (uint64_t)ip; */

next:
        ret = unw_step(&c);
        fail_if(ret < 0, "unw_step");

        if (ret == 0)
            break;
    }

    return head;
}

struct thread* unwind_stacks(Dwfl *dwfl, const char *core_file,
                             struct exec_map *em,
                             struct expr_context *ctx)
{
    unw_addr_space_t as;
    struct UCD_info *ui;
    struct thread *head = NULL, *tail = NULL;

    as = unw_create_addr_space(&_UCD_accessors, 0);
    fail_if(!as, "unw_create_addr_space");

    ui = _UCD_create(core_file);
    fail_if(!ui, "_UCD_create");

    for (; em != NULL; em = em->next)
    {
        if (_UCD_add_backing_file_at_vaddr(ui, em->vaddr, em->file) < 0)
        {
            fail("_UCD_add_backing_file_at_vaddr");
        }
    }

    int tnum;
    int nthreads = _UCD_get_num_threads(ui);
    for (tnum = 0; tnum < nthreads; tnum++)
    {
        struct thread *thread = xalloc(sizeof(struct thread));
        thread->frames = unwind_thread(dwfl, as, ui, tnum, ctx);
        list_append(head, tail, thread);
    }

    return head;
}
