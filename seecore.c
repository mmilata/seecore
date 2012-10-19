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
    debug("dwarf: [%d]%s dwfl: [%d]%s", d, dwarf_errmsg(d), dw, dwfl_errmsg(dw));
}

static int find_elf_core (Dwfl_Module *mod, void **userdata,
                          const char *modname, Dwarf_Addr base,
                          char **file_name, Elf **elfp)
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

static void analyze_type(Dwarf_Die *die, struct type *ty)
{
    int ret;
    Dwarf_Attribute at;

    /* find out the values of name, byte_size and type attributes
     * even though not all of them make sense for all tags
     */
    char *name = NULL;
    if (dwarf_attr(die, DW_AT_name, &at) != NULL)
    {
        name = xstrdup(dwarf_formstring(&at));
    }

    struct type sub_type = { .name = NULL, .width = 0 };
    if (dwarf_attr(die, DW_AT_type, &at) != NULL)
    {
        Dwarf_Die sub_die;
        if (dwarf_formref_die(&at, &sub_die) != NULL)
            analyze_type(&sub_die, &sub_type);
    }

    Dwarf_Word width = 0;
    if (dwarf_attr(die, DW_AT_byte_size, &at) != NULL)
    {
        ret = dwarf_formudata(&at, &width);
        fail_if(ret == -1, "dwarf_formudata");
    }

    switch (dwarf_tag(die))
    {
    case DW_TAG_base_type:
        ty->name = name;
        name = NULL;
        ty->width = (unsigned)width;
        /* TODO: what about encoding? */
        break;

    /* type modifiers */
    case DW_TAG_const_type:
        ty->name = xsprintf("const %s", sub_type.name ?: "void");
        ty->width = sub_type.width;
        break;

    case DW_TAG_pointer_type:
        ty->width = (unsigned)width;
        ty->name = xsprintf("%s*", sub_type.name ?: "void");
        break;

    case DW_TAG_restrict_type:
        ty->name = xsprintf("%s restrict", sub_type.name ?: "void");
        ty->width = sub_type.width;
        break;

    case DW_TAG_volatile_type:
        ty->name = xsprintf("volatile %s", sub_type.name ?: "void");
        ty->width = sub_type.width;
        break;

    case DW_TAG_typedef:
        ty->name = name;
        name = NULL;
        ty->width = sub_type.width;
        break;

    case DW_TAG_array_type:
        ty->name = xsprintf("%s[]", sub_type.name);
        ty->width = 0; /* TODO */
        break;

    case DW_TAG_structure_type:
        if (name)
            ty->name = xsprintf("struct %s", name);
        else
            ty->name = xstrdup("struct");
        ty->width = (unsigned)width;
        break;

    case DW_TAG_union_type:
        if (name)
            ty->name = xsprintf("union %s", name);
        else
            ty->name = xstrdup("union");
        ty->width = (unsigned)width;
        break;

    case DW_TAG_class_type:
        ty->name = xsprintf("class %s", name);
        ty->width = (unsigned)width;
        break;

    case DW_TAG_enumeration_type:
        ty->name = xsprintf("enum %s", name);
        ty->width = (unsigned)width;
        break;

    case DW_TAG_subroutine_type:
        ty->name = xstrdup("FUNCTION");
        ty->width = 0; /* TODO */
        break;

    default:
        warn("Unknown type 0x%x named %s with width %u", dwarf_tag(die), name, (unsigned)width);
        break;
    }

    free(sub_type.name);
    free(name);
}

static void analyze_name_location(Dwarf_Die *die, Dwarf_Files *files,
                                  char **name, struct location* loc)
{
    int ret;
    Dwarf_Attribute at;
    Dwarf_Word w;

    if (dwarf_attr_integrate(die, DW_AT_name, &at) != NULL)
    {
        *name = xstrdup(dwarf_formstring(&at));
    }

    if (dwarf_attr_integrate(die, DW_AT_decl_file, &at) != NULL)
    {
        ret = dwarf_formudata(&at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        loc->file = xstrdup(dwarf_filesrc(files, (size_t)w, NULL, NULL));
    }

    if (dwarf_attr_integrate(die, DW_AT_decl_line, &at) != NULL)
    {
        ret = dwarf_formudata(&at, &w);
        fail_if(ret == -1, "dwarf_formudata");
        loc->line = (unsigned)w;
    }
}

static struct variable* analyze_variable(Dwarf_Die *die, Dwarf_Files *files)
{
    int ret;
    Dwarf_Attribute at;
    struct variable* var;

    /* ignore declarations */
    if (dwarf_attr_integrate(die, DW_AT_declaration, &at) != NULL)
    {
        bool flag;
        ret = dwarf_formflag(&at, &flag);
        fail_if(ret == -1, "dwarf_formflag");
        if (flag)
            return NULL;
    }

    var = xalloc(sizeof(struct variable));
    analyze_name_location(die, files, &var->name, &var->loc);

    if (dwarf_attr_integrate(die, DW_AT_location, &at) != NULL)
    {
        /* TODO TODO TODO */
    }

    if (dwarf_attr_integrate(die, DW_AT_type, &at) != NULL)
    {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&at, &type_die) == NULL)
            fail("dwarf_formref_die");
        analyze_type(&type_die, &(var->type));
    }

    return var;
}

static struct variable* child_variables(Dwarf_Die *parent, Dwarf_Files *files,
                                        bool params)
{
    int ret;
    Dwarf_Die die;
    struct variable *var, *head = NULL, *tail = NULL;
    int desired_tag = params ? DW_TAG_formal_parameter : DW_TAG_variable;

    ret = dwarf_child(parent, &die);
    if (ret != 0)
        return NULL;

    do
    {
        if (dwarf_tag(&die) == desired_tag)
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

static bool supported_language(Dwarf_Die *cu)
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

static struct variable* cu_globals(Dwarf_Die *cu)
{
    int ret;
    Dwarf_Files *files;

    if(!supported_language(cu))
        return NULL;

    ret = dwarf_getsrcfiles(cu, &files, NULL);
    fail_if(ret == -1, "dwarf_getsrcfiles");

    return child_variables(cu, files, false);
}

static int analyze_module(Dwfl_Module *mod, void **userdata, const char *name,
                          Dwarf_Addr start_addr, void *arg)
{
    struct core_contents *core = arg;

    GElf_Addr bias;
    bool have_elf = (dwfl_module_getelf (mod, &bias) != NULL);
    errors();
    bool have_dwarf = (dwfl_module_getdwarf (mod, &bias) != NULL);
    errors();

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

static void read_maps(Elf *e, struct core_contents* core)
{
    int res;
    size_t i, nheaders;
    GElf_Phdr phdr, *p;
    struct data_map **nextmm = &(core->maps);

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
        *nextmm = xalloc(sizeof(struct data_map));
        (*nextmm)->vaddr = (uint64_t)phdr.p_vaddr;
        (*nextmm)->off   = (uint64_t)phdr.p_offset;
        (*nextmm)->len   = (uint64_t)phdr.p_memsz;
        nextmm = &((*nextmm)->next);
    }
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

static struct frame* unwind_thread(Dwfl *dwfl, unw_addr_space_t as,
                                   struct UCD_info *ui, int thread_no)
{
    info("thread %d:", thread_no);

    int i, ret;
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

        unw_word_t off;
        char funcname[10*1024];
        ret = unw_get_proc_name(&c, funcname, sizeof(funcname)-1, &off);
        fail_if(ret < 0, "unw_get_proc_name for IP %lx", (unsigned long)ip);
        info("\t%lx %s", (unsigned long)ip, funcname);

        /* find compilation unit owning the IP */
        Dwarf_Addr bias;
        Dwarf_Die *cu = dwfl_addrdie(dwfl, (Dwarf_Addr)ip, &bias);
        if (!cu)
        {
            warn("\t\tcannot find CU for ip %lx", (unsigned long)ip);
            goto next;
        }

        if (!supported_language(cu))
        {
            warn("\t\tunsupported CU language");
            goto next;
        }

        /* TODO: we have CU - fall back to CU name if subprogram not found */

        Dwarf_Die *scopes;
        int nscopes = dwarf_getscopes(cu, (Dwarf_Addr)ip, &scopes);
        if (nscopes == -1)
        {
            warn("\t\tfailed to get scopes");
            goto next;
        }
        else if (nscopes > 0)
        {
            debug("\t\tscopes:");
            for (i = 0; i < nscopes; i++)
            {
                Dwarf_Die *scope_die = &scopes[i];
                debug("\t\t\ttag: 0x%x", dwarf_tag(&scopes[i]));
            }
        }

        Dwarf_Files *files;
        ret = dwarf_getsrcfiles(cu, &files, NULL);
        fail_if(ret == -1, "dwarf_getsrcfiles");

        for (i = 0; i < nscopes; i++)
        {
            Dwarf_Die *scope_die = &scopes[i];

            //TODO: inlined functions need more thinking
            //  e.g. WTF is the difference between DW_TAG_inlined_subroutine
            //  and DW_TAG_subprogram with DW_AT_abstract_origin

            /* append to frame variables */
            list_append(frame->vars, frame->vars_tail,
                        child_variables(scope_die, files, false));

            if (dwarf_tag(scope_die) == DW_TAG_subprogram)
            {
                /* get function parameters */
                list_append(frame->params, frame->params_tail,
                            child_variables(scope_die, files, true));

                /* add function name to frame struct */
                analyze_name_location(scope_die, files,
                                      &frame->name, &frame->loc);
                info("\t\tfunction name: %s", frame->name);

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

static struct thread* unwind_stacks(Dwfl *dwfl, const char *core_file,
                                    struct exec_map *em)
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
        thread->frames = unwind_thread(dwfl, as, ui, tnum);
        list_append(head, tail, thread);
    }

    return head;
}

struct core_contents* analyze_core(const char *exe_file, const char *core_file)
{
    Dwfl_Callbacks dwcb = {
        .find_elf = find_elf_core,
        .find_debuginfo = dwfl_build_id_find_debuginfo,
        .section_address = dwfl_offline_section_address
    };

    struct core_contents *core = xalloc(sizeof(*core));
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

    info("analyzing globals");
    ptrdiff_t ret;
    ret = dwfl_getmodules(dwfl, analyze_module, core, 0);
    fail_if(ret != 0, "dwfl_getmodules returned %td", ret);

    info("analyzing stacks");
    read_maps(e, core);

    struct exec_map *exec_map = executable_maps(dwfl);
    core->threads = unwind_stacks(dwfl, core_file, exec_map);
    free(exec_map);

    /* TODO: location/value extraction */
    dwfl_end(dwfl);

    return core;
}

static void free_variables(struct variable *v)
{
    struct variable *vx;

    for (; v != NULL; v = vx)
    {
        vx = v->next;
        free(v->loc.file);
        free(v->type.name);
        free(v->name);
        free(v->value);
        free(v);
    }
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

    printf("%s (type: %s size: %u defined: %s:%u)\n",
           var->name,
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

int main(int argc, char *argv[])
{
    /* TODO: investigate DW_TAG_GNU_call_site */
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <binary> <core>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    message_level = 2; /* 0 = nothing, 1 = warn, 2 = info, 3 = debug */

    struct core_contents *c = analyze_core(argv[1], argv[2]);
    print_core(c);
    free_core(c);

    return EXIT_SUCCESS;
}
