#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

int a_global = 666;

void *fun(void * number)
{
        long i;
        int n = (int)number;

        for(i=0;;i++)
        {
                if (i % 500000 == 0)
                        printf("%d\n", n);

                if(i > 100000000 && n==2)
                {
                        *((int *)NULL) = 42;
                        printf("something: %d\n", a_global);
                }
        }
}

int main(int argc, char *argv[])
{
        int i;
        pthread_t thr;

        for(i = 0; i < 4; i++)
        {
                //getchar();
                pthread_create(&thr, NULL, &fun, (void *)i);
        } 

        pthread_join(thr, NULL);

        return 0;
}
