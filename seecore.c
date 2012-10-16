#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>

#include <libelf.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>

#include "seecore.h"

/* Is there any other way we can pass the executable file name to the find_elf
 * callback? */
char *executable_file = NULL;

void errors(void)
{
    int d = dwarf_errno();
    int dw = dwfl_errno();
    //printf("dwarf: [%d]%s dwfl: [%d]%s\n", d, dwarf_errmsg(d), dw, dwfl_errmsg(dw));
}

void append_variable(struct variable** list, struct variable* var)
{
    if (*list == NULL)
    {
        *list = var;
    }
    else
    {
        append_variable(&(*list)->next, var);
    }
}

int my_find_elf (Dwfl_Module *mod, void **userdata, const char *modname, Dwarf_Addr base, char **file_name, Elf **elfp)
{
    int ret;
    const char *dmodname, *elf, *debug;
    dmodname = dwfl_module_info(mod, NULL, NULL, NULL, NULL, NULL, &elf, &debug);

    /*
    printf("<\n\tTrying to find elf:\n");
    printf("\tModule:\t%s (%s,%s)\n", dmodname, elf, debug);
    printf("\tModname:\t%s, base: %ld\n", modname, base);
    */

    if (!strcmp("[exe]", modname))
    {
        //printf("[exe] module\n");
        int fd = open(executable_file, O_RDONLY);
        if (fd < 0)
            return -1;

        *file_name = realpath(executable_file, NULL);
        *elfp = elf_begin(fd, ELF_C_READ, NULL);
        ret = fd;
    }
    else
    {
        ret = dwfl_build_id_find_elf(mod, userdata, modname, base, file_name, elfp);
    }

    /*
    printf("\treturning: %d\n", ret);
    printf(">\n");
    */
    return ret;
}

int my_find_debuginfo (Dwfl_Module *mod, void **userdata, const char *modname, Dwarf_Addr base,
                       const char *file_name, const char *debuglink_file,
                       GElf_Word debuglink_crc, char **debuginfo_file_name)
{
    const char *dmodname, *elf, *debug;
    dmodname = dwfl_module_info(mod, NULL, NULL, NULL, NULL, NULL, &elf, &debug);

    /*
    printf("<\n\tTrying to find debuginfo:\n");
    printf("\tModule:\t%s (%s,%s)\n", dmodname, elf, debug);
    printf("\tModname:\t%s, base: %ld\n", modname, base);
    printf("\tFilename:\t%s, debuglink: %s\n", file_name, debuglink_file);
    */

    int ret = dwfl_build_id_find_debuginfo(mod, userdata, modname, base, file_name, debuglink_file, debuglink_crc, debuginfo_file_name);
    /*
    printf("\treturning: %d\n", ret);
    printf(">\n");
    */
    return ret;
}

#if 0
int print_attr(Dwarf_Attribute *at, void *data)
{
    unsigned indent = (unsigned)data;
    //printf("\tcode: %x\tform: %x\tstring: %s\n", dwarf_whatattr(at), dwarf_whatform(at), dwarf_formstring(at));
    unsigned int what = dwarf_whatattr(at);

    if (what == DW_AT_name)
    {
        for (; indent > 0; indent--)
            printf("\t");
        printf("name: %s\n", dwarf_formstring(at));
    }
    else if (what == DW_AT_location)
    {
        for (; indent > 0; indent--)
            printf("\t");
        Dwarf_Block block;
        printf("location: (form: %x)", dwarf_whatform(at));

        dwarf_formblock(at, &block);
        printf(" len: %lx", block.length);
        printf("\n");
    }

    return DWARF_CB_OK;
}

int print_die(Dwarf_Die *die)
{
    printf("\ttag: 0x%x\n", dwarf_tag(die));
    dwarf_getattrs(die, print_attr, (void *)2, 0);

    return 0;
}
#endif

/* now i remember why i hate c */
struct cb_var_attrs_arg
{
    struct variable *var;
    Dwarf_Files *files;
};

static int cb_var_attrs(Dwarf_Attribute *at, void *arg)
{
    struct cb_var_attrs_arg *a = arg;
    int ret;
    bool flag;
    Dwarf_Word w;

    //printf("%x\n", dwarf_whatattr(at));
    switch (dwarf_whatattr(at))
    {
    case DW_AT_name:
        a->var->name = xstrdup(dwarf_formstring(at));
        //printf("name: %s\n", var->name);
        break;
    case DW_AT_decl_file:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->var->location.file = xstrdup(dwarf_filesrc(a->files, (size_t)w, NULL, NULL));
        break;
    case DW_AT_decl_line:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->var->location.line = (unsigned)w;
        break;
    case DW_AT_location:
        /* TODO */
        break;
    case DW_AT_type:
        /* TODO */
        break;
    case DW_AT_declaration:
        ret = dwarf_formflag(at, &flag);
        fail_if(ret == -1, "dwarf_formflag");
        if (flag)
            return DWARF_CB_ABORT;
        break;
    default:
        break;
    }

    return DWARF_CB_OK;
}

struct variable* analyze_variable(Dwarf_Die *die, Dwarf_Files *files)
{
    ptrdiff_t ret;
    struct cb_var_attrs_arg arg;
    arg.files = files;
    arg.var = xalloc(sizeof(struct variable));

    ret = dwarf_getattrs(die, cb_var_attrs, &arg, 0);
    fail_if(ret == -1, "dwarf_getattrs");

    if (ret != 1)
    {
        free(arg.var);
        return NULL;
    }

    return arg.var;
}

int cu_globals(Dwarf_Die *cu, struct core_contents *core)
{
#if 0
    int cb_cu_name(Dwarf_Attribute *at, void *arg)
    {
        char **out = arg;

        if (dwarf_whatattr(at) == DW_AT_name)
        {
            *out = xstrdup(dwarf_formstring(at));
            return DWARF_CB_ABORT;
        }
        return DWARF_CB_OK;
    }

    /* cu file not actually used? */
    char *cu_file = NULL;
    ret = dwarf_getattrs(cu, cb_cu_name, &cu_file, 0);
    if (ret == -1)
        fail("dwarf_getattrs");
    printf("CU FILE: %s\n", cu_file);
#endif

    int ret;
    struct variable *var;
    Dwarf_Die die;
    Dwarf_Files *files;

    ret = dwarf_getsrcfiles(cu, &files, NULL);
    fail_if(ret == -1, "dwarf_getsrcfiles");

    ret = dwarf_child(cu, &die);
    if (ret == 0)
    {
        do
        {
            if (dwarf_tag(&die) == DW_TAG_variable)
            {
                //print_die(&die);
                var = analyze_variable(&die, files);
                if (!var)
                    continue;

                /* XXX */
                if (var->name && var->name[0] == '_')
                {
                    free(var);
                    continue;
                }

                /* XXX append */
                append_variable(&core->globals, var);
            }
        } while (dwarf_siblingof(&die, &die) == 0);
    }

    return 0;
}

int analyze_module(Dwfl_Module *mod, void **userdata, const char *name, Dwarf_Addr start_addr, void *arg)
{
    struct core_contents *core = arg;

    GElf_Addr bias;
    bool have_elf = (dwfl_module_getelf (mod, &bias) != NULL);
    errors();
    bool have_dwarf = (dwfl_module_getdwarf (mod, &bias) != NULL);
    errors();

#if 0
    Dwarf_Addr start, end, dwbias, symbias;
    const char *mainfile, *debugfile;
    dwfl_module_info(mod, NULL, &start, &end, NULL, NULL, &mainfile, &debugfile);
    printf("%s 0x%lx+%lx\n", name, start, end-start);
    printf("\tmain: %s, debug: %s\n", /*dwbias, symbias,*/ mainfile, debugfile);
    printf("\telf: %d, dwarf: %d\n", have_elf, have_dwarf);
#endif

    if (!have_dwarf)
        return DWARF_CB_OK;

    Dwarf_Addr cubias;
    Dwarf_Die *die = NULL;

    while ((die = dwfl_module_nextcu(mod, die, &cubias)))
    {
        cu_globals(die, core/*, cubias*/);
    }

    return DWARF_CB_OK;
}

void read_maps(Elf *e, struct core_contents* core)
{
    int res;
    size_t i, nheaders;
    GElf_Phdr phdr, *p;
    struct mem_map **nextmm = &(core->maps);

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

        /* assume writable for now */
        if ((phdr.p_flags & PF_W) == 0)
            continue;

        /* not executable */
        if ((phdr.p_flags & PF_X) != 0)
            continue;

        /* skip incomplete segments */
        if (phdr.p_filesz != phdr.p_memsz)
            continue;

        *nextmm = xalloc(sizeof(struct mem_map));
        (*nextmm)->vaddr = (uint64_t)phdr.p_vaddr;
        (*nextmm)->off   = (uint64_t)phdr.p_offset;
        (*nextmm)->len   = (uint64_t)phdr.p_memsz;
        nextmm = &((*nextmm)->next);
        //printf("0x%lx+%lx at offset 0x%lx\n", (unsigned long)phdr.p_vaddr, (unsigned long)phdr.p_memsz, (unsigned long)phdr.p_offset);
    }
}

struct core_contents* analyze_core(char *exe_file, char *core_file)
{
    Dwfl_Callbacks dwcb = {
        .find_elf = my_find_elf, //dwfl_build_id_find_elf,
        .find_debuginfo = my_find_debuginfo, //dwfl_build_id_find_debuginfo,
        .section_address = dwfl_offline_section_address
    };

    struct core_contents *core = xalloc(sizeof(*core));

    /* call only once? */
    if (elf_version(EV_CURRENT) == EV_NONE)
        fail("elf_version");

    int fd = open(core_file, O_RDONLY);
    if (fd < 0)
        fail("open");

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    fail_if(e == NULL, "elf_begin");
    fail_if(elf_kind(e) != ELF_K_ELF, "elf_kind");

    Dwfl *dwfl = dwfl_begin(&dwcb);

    executable_file = exe_file;
    /*
    if (!dwfl_report_offline(dwfl, "[exe]", exe_file, -1))
        fail("dwfl_report_offline");
        */

    if (dwfl_core_file_report(dwfl, e) == -1)
        fail("dwfl_core_file_report");

    if (dwfl_report_end(dwfl, NULL, NULL) != 0)
        fail("dwfl_report_end");

    ptrdiff_t ret;
    ret = dwfl_getmodules(dwfl, analyze_module, core, 0);
    fail_if(ret != 0, "dwfl_getmodules returned %td", ret);

    read_maps(e, core);

    /* TODO: stacks */
    /* TODO: location/value extraction */

    return core;
}

void print_core(struct core_contents *core)
{
    struct variable *v;
    struct mem_map *m;

    printf("GLOBALS:\n");
    for (v = core->globals; v != NULL; v = v->next)
    {
        printf("\t%s (%s:%u)\n",
               v->name,
               strrchr(v->location.file, '/')+1,
               v->location.line);
    }

    printf("\nMEMORY MAPPING: (vaddr -> offset (size))\n");
    for (m = core->maps; m != NULL; m = m->next)
    {
        printf("\t0x%" PRIx64 " -> 0x%" PRIx64 " (%" PRIu64 "B)\n",
               m->vaddr, m->off, m->len);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <binary> <core>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct core_contents *c = analyze_core(argv[1], argv[2]);
    print_core(c);


    return EXIT_SUCCESS;
}
