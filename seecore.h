struct location
{
    char*    file;
    unsigned line;
    /* column ? */
};

struct variable
{
    char*            name;
    unsigned         width;
    char*            value;
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
        if ((_tmp) == NULL)                  \
            break;                           \
        if ((head) == NULL)                  \
        {                                    \
            (head) = (tail) = (_tmp);        \
        }                                    \
        else                                 \
        {                                    \
            (tail)->next = (_tmp);           \
            while ((tail)->next)             \
                (tail) = (tail)->next;       \
        }                                    \
    } while(0)

void fail(const char *fmt, ...);
void fail_if(int p, const char *fmt, ...);
char* xstrdup(const char *s);
void* xalloc(size_t size);
