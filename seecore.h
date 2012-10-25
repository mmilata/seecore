#include <libunwind-coredump.h>

struct location
{
    char*    file;
    unsigned line;
    /* column ? */
};

struct type
{
    char*    name;  /* useless for anything except human consumption */
    unsigned width;
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
    /* TODO: address / line */
    char*            name;
    struct location  loc;
    struct variable* vars;
    struct variable* vars_tail; /* O(1) list append */
    struct variable* params;
    struct variable* params_tail;
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

/* maps executable segments to their backing files - needed by libunwind */
struct exec_map
{
    uint64_t         vaddr;
    char*            file;
    struct exec_map* next;
};

struct core_contents
{
    struct variable* globals;
    struct variable* globals_tail;
    struct thread*   threads;
    struct data_map* maps;
};

struct expr_context
{
    unw_cursor_t *curs;
    int core_fd;
    struct data_map *maps;
    Dwarf_Addr ip;
    Dwarf_Addr cfa;
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

void fail(const char *fmt, ...);
void fail_if(int p, const char *fmt, ...);
char* xsprintf(const char *fmt, ...);
char* xstrdup(const char *s);
void* xalloc(size_t size);

extern int message_level;
void message(int level, const char *fmt, ...);

unsigned char* evaluate_loc_expr(Dwarf_Op *expr, size_t expr_len, struct expr_context *ctx, size_t data_len);

#define warn(...)  message(1, __VA_ARGS__)
#define info(...)  message(2, __VA_ARGS__)
#define debug(...) message(3, __VA_ARGS__)
