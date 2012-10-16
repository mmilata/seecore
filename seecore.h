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

struct core_contents
{
    /* address -> core maps */
    struct variable* globals;
    struct thread*   threads;
};

void fail(const char *fmt, ...);
void fail_if(int p, const char *fmt, ...);
char* xstrdup(const char *s);
void* xalloc(size_t size);
