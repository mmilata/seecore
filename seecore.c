#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>

#include <libelf.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>

#include <libunwind-coredump.h>

#include "seecore.h"

/* Is there any other way we can pass the executable file name to the find_elf
 * callback? */
const char *executable_file = NULL;

void errors(void)
{
    int d = dwarf_errno();
    int dw = dwfl_errno();
    //printf("dwarf: [%d]%s dwfl: [%d]%s\n", d, dwarf_errmsg(d), dw, dwfl_errmsg(dw));
}

int my_find_elf (Dwfl_Module *mod, void **userdata, const char *modname, Dwarf_Addr base, char **file_name, Elf **elfp)
{
    int ret = -1;

    if (!strcmp("[exe]", modname))
    {
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

    return ret;
}

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

    switch (dwarf_whatattr(at))
    {
    case DW_AT_name:
        a->var->name = xstrdup(dwarf_formstring(at));
        //printf("name: %s\n", a->var->name);
        break;
    case DW_AT_decl_file:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->var->loc.file = xstrdup(dwarf_filesrc(a->files, (size_t)w, NULL, NULL));
        break;
    case DW_AT_decl_line:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->var->loc.line = (unsigned)w;
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

struct variable* child_variables(Dwarf_Die *parent, Dwarf_Files *files)
{
    int ret;
    Dwarf_Die die;
    struct variable *var, *head = NULL, *tail = NULL;

    ret = dwarf_child(parent, &die);
    if (ret != 0)
        return NULL;

    do
    {
        if (dwarf_tag(&die) == DW_TAG_variable)
        {
            var = analyze_variable(&die, files);
            if (!var)
                continue;

            /* XXX */
            if (var->name && var->name[0] == '_')
            {
                free(var);
                continue;
            }

            list_append(head, tail, var);
        }
    } while (dwarf_siblingof(&die, &die) == 0);

    return head;
}

struct variable* cu_globals(Dwarf_Die *cu)
{
    int ret;
    Dwarf_Files *files;
    Dwarf_Attribute at;
    Dwarf_Word lang;

    if (dwarf_attr(cu, DW_AT_language, &at) == NULL)
    {
        fprintf(stderr, "CU %s: unknown language\n",
                dwarf_diename(cu));
        return NULL;
    }

    ret = dwarf_formudata(&at, &lang);
    fail_if(ret == -1, "dwarf_formudata");

    switch (lang)
    {
    case DW_LANG_C89:
    case DW_LANG_C:
    case DW_LANG_C99:
        /* supported language */
        break;
    case DW_LANG_C_plus_plus:
        fail("C++ not supported");
        /* TODO: return NULL instead */
        break;
    default:
        /*
        fprintf(stderr, "CU %s: unsupported language: 0x%lx\n",
                dwarf_diename(cu), (unsigned long)lang);
        */
        return NULL;
        break;
    }

    ret = dwarf_getsrcfiles(cu, &files, NULL);
    fail_if(ret == -1, "dwarf_getsrcfiles");

    return child_variables(cu, files);
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
        /* TODO: sometimes, CU is analyzed multiple times - investigate */
        list_append(core->globals, core->globals_tail, cu_globals(die));
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

        /* append to list */
        *nextmm = xalloc(sizeof(struct mem_map));
        (*nextmm)->vaddr = (uint64_t)phdr.p_vaddr;
        (*nextmm)->off   = (uint64_t)phdr.p_offset;
        (*nextmm)->len   = (uint64_t)phdr.p_memsz;
        nextmm = &((*nextmm)->next);
    }
}

static int cb_exe_maps(Dwfl_Module *mod, void **userdata, const char *name, Dwarf_Addr start_addr, void *arg)
{
    /* pointer madness! */
    struct exe_map ***tailp = arg;
    const char *elf_file = NULL;
    Dwarf_Addr base;

    dwfl_module_info(mod, NULL, &base, NULL, NULL, NULL, &elf_file, NULL);

    if (elf_file)
    {
        **tailp = xalloc(sizeof(struct exe_map));
        (**tailp)->vaddr = (uint64_t)base;
        (**tailp)->file = xstrdup(elf_file);
        *tailp = &((**tailp)->next);
    }

    return DWARF_CB_OK;
}

/* This HAS TO be called AFTER dwfl_getmodules(..., analyze_module, ...) as the
 * file names are resolved lazily and may not be available (or call
 * dwfl_module_getelf). */
struct exe_map* executable_maps(Dwfl *dwfl)
{
    ptrdiff_t ret;
    struct exe_map *head = NULL;
    struct exe_map **tail = &head;

    ret = dwfl_getmodules(dwfl, cb_exe_maps, &tail, 0);
    fail_if(ret == -1, "dwfl_getmodules");

    return head;
}

/* TODO: factor out common code from variable attrs callback */
/* this vvv is UGLY */
struct cb_subprogram_attrs_arg
{
    struct frame *frame;
    Dwarf_Files *files;
};

static int cb_subprogram_attrs(Dwarf_Attribute *at, void *arg)
{
    struct cb_subprogram_attrs_arg *a = arg;
    int ret;
    bool flag;
    Dwarf_Word w;

    switch (dwarf_whatattr(at))
    {
    case DW_AT_name:
        a->frame->name = xstrdup(dwarf_formstring(at));
        break;
    case DW_AT_decl_file:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->frame->loc.file = xstrdup(dwarf_filesrc(a->files, (size_t)w, NULL, NULL));
        break;
    case DW_AT_decl_line:
        ret = dwarf_formudata(at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        a->frame->loc.line = (unsigned)w;
        break;
    default:
        break;
    }

    return DWARF_CB_OK;
}

struct frame* unwind_thread(Dwfl *dwfl, unw_addr_space_t as, struct UCD_info *ui, int thread_no, struct core_contents *core)
{
    printf("Thread %d:\n", thread_no);

    int ret;
    unw_cursor_t c;

    _UCD_select_thread(ui, thread_no);

    ret = unw_init_remote(&c, as, ui);
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

        struct frame *frame = xalloc(sizeof(struct frame));
        list_append(head, tail, frame);
        /* TODO: frame IP */

        printf("\t%lx\n", (unsigned long)ip);
        unw_word_t off;
        char funcname[10*1024];
        ret = unw_get_proc_name(&c, funcname, sizeof(funcname)-1, &off);
        printf("\t\t%s\n", funcname);
        fail_if(ret < 0, "unw_get_proc_name");

        /* find compilation unit owning the IP */
        Dwarf_Addr bias;
        Dwarf_Die *cu = dwfl_addrdie(dwfl, (Dwarf_Addr)ip, &bias);
        if (!cu)
        {
            printf("\t\tcannot find CU for ip %lx\n", (unsigned long)ip);
            goto next;
        }

        /* TODO: we have CU - fall back to CU name if subprogram not found */

        Dwarf_Die *scopes;
        int nscopes = dwarf_getscopes(cu, (Dwarf_Addr)ip, &scopes);
        //fail_if(ret == -1, "dwarf_getscopes");
        if (nscopes == -1)
        {
            printf("\t\tfailed to get scopes\n");
            goto next;
        }

        Dwarf_Files *files;
        ret = dwarf_getsrcfiles(cu, &files, NULL);
        fail_if(ret == -1, "dwarf_getsrcfiles");

        int i;
        for (i = 0; i < nscopes; i++)
        {
            Dwarf_Die *scope_die = &scopes[i];
            //printf("\t\t\tscope tag %x\n", dwarf_tag(&scopes[i]));

            //append to frame variables
            list_append(frame->vars, frame->vars_tail, /* TODO: get rid of tail? */
                        child_variables(scope_die, files));

            if (dwarf_tag(scope_die) == DW_TAG_subprogram)
            {
                /* add function name to frame struct */
                struct cb_subprogram_attrs_arg arg;
                arg.frame = frame;
                arg.files = files;
                dwarf_getattrs(scope_die, cb_subprogram_attrs, &arg, 0);
                printf("\t\tfunction: %s\n", frame->name);

                /* do not continue over subprogram boundary */
                break;
            }
        }

        //??? free(scopes);

next:
        ret = unw_step(&c);
        fail_if(ret < 0, "unw_step");

        if (ret == 0)
            break;
    }

    return head;
}

struct thread* unwind_stacks(Dwfl *dwfl, const char *core_file, struct core_contents *core, struct exe_map *em)
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
        thread->frames = unwind_thread(dwfl, as, ui, tnum, core);
        list_append(head, tail, thread);
    }

    return head;
}

struct core_contents* analyze_core(const char *exe_file, const char *core_file)
{
    Dwfl_Callbacks dwcb = {
        .find_elf = my_find_elf, //dwfl_build_id_find_elf,
        .find_debuginfo = dwfl_build_id_find_debuginfo,
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

    if (dwfl_core_file_report(dwfl, e) == -1)
        fail("dwfl_core_file_report");

    if (dwfl_report_end(dwfl, NULL, NULL) != 0)
        fail("dwfl_report_end");

    ptrdiff_t ret;
    ret = dwfl_getmodules(dwfl, analyze_module, core, 0);
    fail_if(ret != 0, "dwfl_getmodules returned %td", ret);

    read_maps(e, core);

    /* TODO: stacks */
    core->threads = unwind_stacks(dwfl, core_file, core, executable_maps(dwfl));

    /* TODO: location/value extraction */

    return core;
}

void print_core(struct core_contents *core)
{
    struct variable *v;
    struct mem_map *m;
    struct thread *t;
    struct frame *f;

    printf("GLOBALS:\n");
    for (v = core->globals; v != NULL; v = v->next)
    {
        printf("\t%s (%s:%u)\n",
               v->name,
               strrchr(v->loc.file, '/')+1,
               v->loc.line);
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
            for (v = f->vars; v != NULL; v = v->next)
            {
                printf("\t\t%s (%s:%u)\n",
                       v->name,
                       strrchr(v->loc.file, '/')+1,
                       v->loc.line);
            }
        }
        printf("\n");
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
