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
    struct location  location;
    struct variable* next;
};

struct frame
{
    /* address */
    /* function symbol + location */
    /* offset */
    /* variables */
    /* next */
    struct frame* next;
};

struct thread
{
    struct frame*  frames;
    struct thread* next;
};

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
    struct thread*   threads;
    struct mem_map*  maps;
};

void fail(const char *fmt, ...);
void fail_if(int p, const char *fmt, ...);
char* xstrdup(const char *s);
void* xalloc(size_t size);
