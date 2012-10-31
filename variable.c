/*
 * Written by Martin Milata in 2012.
 * Published under WTFPL, see LICENSE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <elfutils/libdw.h>
#include <dwarf.h>

#include "seecore-internal.h"

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
        ty->width = POINTER_SIZE;
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

void analyze_name_location(Dwarf_Die *die, Dwarf_Files *files,
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

static struct variable* analyze_variable(Dwarf_Die *die, Dwarf_Files *files,
                                         struct expr_context *ctx)
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

    if (dwarf_attr_integrate(die, DW_AT_type, &at) != NULL)
    {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&at, &type_die) == NULL)
            fail("dwarf_formref_die");
        analyze_type(&type_die, &(var->type));
    }

    if (dwarf_attr_integrate(die, DW_AT_const_value, &at) != NULL)
    {
        Dwarf_Word w;
        Dwarf_Block bl;
        unsigned int form = dwarf_whatform(&at);
        debug("variable %s has constant value of form %x", var->name, form);

        if (dwarf_formudata(&at, &w) == 0)
        {
            fail_if(sizeof(w) < var->type.width, "constant value too small");
            var->value = xalloc(var->type.width);
            memcpy(var->value, &w, var->type.width);
        }
        else if (dwarf_formblock(&at, &bl) == 0)
        {
            fail_if(bl.length < var->type.width, "constant value too small");
            var->value = xalloc(var->type.width);
            memcpy(var->value, bl.data, var->type.width);
        }
        else
        {
            warn("unable to get constant value of variable %x (form %x)", var->name, form);
        }
    }
    else if (dwarf_attr_integrate(die, DW_AT_location, &at) != NULL)
    {
        size_t exprlen;
        Dwarf_Op *expr;

        ret = dwarf_getlocation_addr(&at, ctx->ip, &expr, &exprlen, 1);
        if (ret != 1)
        {
            if (ret == -1)
                /* it seems that elfutils have some kind of problem with
                 * DW_OP_GNU_entry_value but that operation is useless for us
                 * anyway */
                warn("cannot get location for variable %s (ip: %lx), %s", var->name, ctx->ip, dwarf_errmsg(-1));
            else if (ret == 0)
                debug("no location available for variable %s (ip: %lx)", var->name, ctx->ip);
            else
                fail("unreachable reached");
            return var;
        }

        var->value = evaluate_loc_expr(expr, exprlen, ctx, var->type.width);
    }

    return var;
}

void free_variables(struct variable *v)
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

struct variable* child_variables(Dwarf_Die *parent, Dwarf_Files *files,
                                 struct expr_context *ctx, bool params)
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
            var = analyze_variable(&die, files, ctx);
            if (!var)
                continue;

            /* XXX */
            if (var->name && var->name[0] == '_')
            {
                free_variables(var);
                continue;
            }

            list_append(head, tail, var);
        }
    } while (dwarf_siblingof(&die, &die) == 0);

    return head;
}
