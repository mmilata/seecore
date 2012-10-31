#ifndef SEECORE_H
#define SEECORE_H

struct type
{
    char*    name;  /* useless for anything except human consumption */
    unsigned width;
};

struct location
{
    char*    file;
    unsigned line;
};

struct variable
{
    char*            name;
    unsigned char*   value;
    struct type      type;
    struct location  loc;
    struct variable* next;
};

struct frame
{
    char*            name;
    struct location  loc;
    struct variable* vars;
    struct variable* vars_tail; /* O(1) list append */
    struct variable* params;
    struct variable* params_tail;
    /* TODO: address / line */
    struct frame*    next;
};

struct thread
{
    struct frame*  frames;
    struct thread* next;
};

/* maps data segments to their offsets in coredump file */
struct data_map
{
    uint64_t         vaddr; /* starting memory addr */
    uint64_t         off;   /* offset in coredump */
    uint64_t         len;   /* length */
    struct data_map* next;
};

struct core_contents
{
    struct variable* globals;
    struct variable* globals_tail;
    struct thread*   threads;
    struct data_map* maps;
};

struct core_contents* analyze_core(const char *exe_file, const char *core_file);
void print_core(struct core_contents *core);
void free_core(struct core_contents *core);

#endif /* SEECORE_H */
