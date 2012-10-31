/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */
/* TODO: investigate DW_TAG_GNU_call_site:
 * http://gcc.gnu.org/wiki/summit2010?action=AttachFile&do=get&target=jelinek.pdf
 * http://gcc.gnu.org/ml/gcc-patches/2010-08/txt00153.txt */
/* TODO: decompose structs into members   */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>

#include <libelf.h>
#include <elfutils/libdwfl.h>

#include "seecore-internal.h"

/* Is there any other way we can pass the executable file name to the find_elf
 * callback? */
const char *executable_file = NULL;

static int find_elf_core (Dwfl_Module *mod, void **userdata,
                          const char *modname, Dwarf_Addr base,
                          char **file_name, Elf **elfp)
{
    int ret = -1;

    if (!strcmp("[exe]", modname) || !strcmp("[pie]", modname))
    {
        int fd = open(executable_file, O_RDONLY);
        if (fd < 0)
            return -1;

        *file_name = realpath(executable_file, NULL);
        *elfp = elf_begin(fd, ELF_C_READ, NULL);
        if (*elfp == NULL)
        {
            warn("Unable to open executable '%s': %s", executable_file, elf_errmsg(-1));
            return -1;
        }

        ret = fd;
    }
    else
    {
        ret = dwfl_build_id_find_elf(mod, userdata, modname, base, file_name, elfp);
    }

    return ret;
}

static struct variable* cu_globals(Dwarf_Die *cu, struct expr_context *ctx)
{
    int ret;
    Dwarf_Files *files;

    if(!supported_language(cu))
        return NULL;

    ret = dwarf_getsrcfiles(cu, &files, NULL);
    fail_if(ret == -1, "dwarf_getsrcfiles");

    return child_variables(cu, files, ctx, false);
}

struct analyze_module_arg
{
    struct core_contents *core;
    struct expr_context *ctx;
};
static int analyze_module(Dwfl_Module *mod, void **userdata, const char *name,
                          Dwarf_Addr start_addr, void *arg)
{
    struct analyze_module_arg *a = arg;

    GElf_Addr bias;
    bool have_elf = (dwfl_module_getelf (mod, &bias) != NULL);
    if (!have_elf)
    {
        warn("Cannot locate ELF file for %s: %s", name, dwfl_errmsg(-1));
        return DWARF_CB_OK;
    }

    bool have_dwarf = (dwfl_module_getdwarf (mod, &bias) != NULL);
    if (!have_dwarf)
    {
        warn("Cannot locate debugging information for %s: %s", name,
             dwfl_errmsg(-1));
        return DWARF_CB_OK;
    }

    Dwarf_Die *die = NULL;

    if (strncmp("libc.so", name, 7) == 0)
        return DWARF_CB_OK;

    while ((die = dwfl_module_nextcu(mod, die, &(a->ctx->bias))))
    {
        /* TODO: sometimes, CU is analyzed multiple times - investigate */
        list_append(a->core->globals, a->core->globals_tail,
                    cu_globals(die, a->ctx));
    }

    return DWARF_CB_OK;
}

static struct data_map* read_maps(Elf *e)
{
    /* TODO: read-only sections in other files */
    /* or is it? we couldn't change them so what's the point? */

    int res;
    size_t i, nheaders;
    GElf_Phdr phdr, *p;
    struct data_map *head = NULL, *tail = NULL, *map;

    res = elf_getphdrnum(e, &nheaders);
    fail_if(res != 0, "elf_getphdrnum");

    for (i = 0; i < nheaders; i++)
    {
        p = gelf_getphdr(e, i, &phdr);
        fail_if(p != &phdr, "gelf_getphdr");

        if (phdr.p_type != PT_LOAD)
            continue;

        /* segment has to be readable */
        if ((phdr.p_flags & PF_R) == 0)
            continue;

#if 0
        /* assume writable for now */
        if ((phdr.p_flags & PF_W) == 0)
            continue;

        /* not executable */
        if ((phdr.p_flags & PF_X) != 0)
            continue;
#endif

        /* skip incomplete segments */
        if (phdr.p_filesz != phdr.p_memsz)
            continue;

        /* append to list */
        map = xalloc(sizeof(struct data_map));
        map->vaddr = (uint64_t)phdr.p_vaddr;
        map->off   = (uint64_t)phdr.p_offset;
        map->len   = (uint64_t)phdr.p_memsz;
        debug("map: %lx - %lx", map->vaddr, map->vaddr + map->len);
        list_append(head, tail, map);
    }

    return head;
}

static int cb_exe_maps(Dwfl_Module *mod, void **userdata, const char *name,
                       Dwarf_Addr start_addr, void *arg)
{
    /* pointer madness! */
    struct exec_map ***tailp = arg;
    const char *elf_file = NULL;
    Dwarf_Addr base;

    dwfl_module_info(mod, NULL, &base, NULL, NULL, NULL, &elf_file, NULL);

    if (elf_file)
    {
        **tailp = xalloc(sizeof(struct exec_map));
        (**tailp)->vaddr = (uint64_t)base;
        (**tailp)->file = xstrdup(elf_file);
        *tailp = &((**tailp)->next);
    }

    return DWARF_CB_OK;
}

/* This HAS TO be called AFTER dwfl_getmodules(..., analyze_module, ...) as the
 * file names are resolved lazily and may not be available (or call
 * dwfl_module_getelf). */
static struct exec_map* executable_maps(Dwfl *dwfl)
{
    ptrdiff_t ret;
    struct exec_map *head = NULL;
    struct exec_map **tail = &head;

    ret = dwfl_getmodules(dwfl, cb_exe_maps, &tail, 0);
    fail_if(ret == -1, "dwfl_getmodules");

    return head;
}

void free_core(struct core_contents *core)
{
    struct data_map *m, *mx;
    struct thread *t, *tx;
    struct frame *f, *fx;

    free_variables(core->globals);

    for (m = core->maps; m != NULL; m = mx)
    {
        mx = m->next;
        free(m);
    }

    for (t = core->threads; t != NULL; t = tx)
    {
        tx = t->next;

        for (f = t->frames; f != NULL; f = fx)
        {
            fx = f->next;
            free_variables(f->params);
            free_variables(f->vars);
            free(f->loc.file);
            free(f->name);
            free(f);
        }

        free(t);
    }
}

static void print_var(struct variable *var, unsigned indent)
{
    unsigned i;
    for (i = 0; i < indent; i++)
        printf("\t");

    printf("%s = ", var->name);

    if (var->value && var->type.width > 16)
    {
        printf("[toolong]");
    }
    else if (var->value)
    {
        for (i = var->type.width; i > 0; i--)
        {
            printf("%02hhx", var->value[i-1]);
        }
    }
    else
    {
        printf("[UNKNOWN]");
    }

    printf(" (type: %s size: %u defined: %s:%u)\n",
           var->type.name,
           var->type.width,
           strrchr(var->loc.file, '/')+1,
           var->loc.line);
}
void print_core(struct core_contents *core)
{
    struct variable *v;
    struct data_map *m;
    struct thread *t;
    struct frame *f;

    printf("GLOBALS:\n");
    for (v = core->globals; v != NULL; v = v->next)
    {
        print_var(v, 1);
    }

    printf("\nMEMORY MAPPING: (vaddr -> offset (size))\n");
    for (m = core->maps; m != NULL; m = m->next)
    {
        printf("\t0x%"PRIx64" -> 0x%"PRIx64" (%"PRIu64"B)\n",
               m->vaddr, m->off, m->len);
    }

    printf("\nTHREADS:\n");
    int tn;
    for (t = core->threads, tn = 0; t != NULL; t = t->next, tn++)
    {
        printf("\tThread %d\n", tn);
        for (f = t->frames; f != NULL; f = f->next)
        {
            printf("\tFrame %s (%s:%u)\n", f->name, f->loc.file, f->loc.line);
            if (f->params)
                printf("\tArguments:\n");
            for (v = f->params; v != NULL; v = v->next)
            {
                print_var(v, 2);
            }
            if (f->vars)
                printf("\tVariables:\n");
            for (v = f->vars; v != NULL; v = v->next)
            {
                print_var(v, 2);
            }
        }
        printf("\n");
    }
}

struct core_contents* analyze_core(const char *exe_file, const char *core_file)
{
    Dwfl_Callbacks dwcb = {
        .find_elf = find_elf_core,
        .find_debuginfo = dwfl_build_id_find_debuginfo,
        .section_address = dwfl_offline_section_address
    };

    struct core_contents *core = xalloc(sizeof(*core));
    struct expr_context ctx;
    static bool libelf_initialized = false;

    if (!libelf_initialized)
    {
        if (elf_version(EV_CURRENT) == EV_NONE)
            fail("elf_version");
        libelf_initialized = true;
    }

    int fd = open(core_file, O_RDONLY);
    if (fd < 0)
        fail("open");

    /* TODO: shall we release the Elf handle ourselves? */
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    fail_if(e == NULL, "elf_begin");
    fail_if(elf_kind(e) != ELF_K_ELF, "elf_kind");

    Dwfl *dwfl = dwfl_begin(&dwcb);

    executable_file = exe_file;

    if (dwfl_core_file_report(dwfl, e) == -1)
        fail("dwfl_core_file_report");

    if (dwfl_report_end(dwfl, NULL, NULL) != 0)
        fail("dwfl_report_end");

    info("analyzing data segment mappings");
    core->maps = read_maps(e);

    ctx.maps = core->maps;
    /* XXX is fd owned by libdw? do we need to copy it? */
    ctx.core_fd = fd;
    ctx.curs = NULL;
    ctx.ip = 0;
    ctx.cfa = 0;

    info("analyzing globals");
    ptrdiff_t ret;
    struct analyze_module_arg arg = { .core = core, .ctx = &ctx };
    ret = dwfl_getmodules(dwfl, analyze_module, &arg, 0);
    fail_if(ret != 0, "dwfl_getmodules returned %td", ret);

    info("analyzing stacks");
    struct exec_map *exec_map = executable_maps(dwfl);
    core->threads = unwind_stacks(dwfl, core_file, exec_map, &ctx);
    free(exec_map);

    dwfl_end(dwfl);

    return core;
}
