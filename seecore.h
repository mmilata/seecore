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
    char*            value;
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

/* TODO: rename to data_map */
struct mem_map
{
    uint64_t        vaddr; /* starting memory addr */
    uint64_t        off;   /* offset in coredump */
    uint64_t        len;   /* length */
    struct mem_map* next;
};

struct core_contents
{
    /* address -> core maps */
    struct variable* globals;
    struct variable* globals_tail;
    struct thread*   threads;
    struct mem_map*  maps;
};

struct exe_map
{
    uint64_t        vaddr;
    char*           file;
    struct exe_map* next;
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

#define warn(...)  message(1, __VA_ARGS__)
#define info(...)  message(2, __VA_ARGS__)
#define debug(...) message(3, __VA_ARGS__)
