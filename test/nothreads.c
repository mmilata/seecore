#include <stdio.h>
#include <stdlib.h>

int a_global;

void g(char c)
{
    char tmp = '>';

    putchar(tmp);
    putchar(c);
    putchar('\n');
    fflush(stdout);

    *((int *)42) = 666;
    printf("done!\n");
}

double f(int a, char b)
{
    double tmp = 42.0;
    a_global++;

    if (a == 0)
        g(b);
    else
        f(0, b+1);

    return tmp;
}

int main(int argc, char *argv[])
{
    char input;
    if (argc > 1 && argv[1])
        input = argv[1][1];
    else
        input = 'a';

    double result = f(666, input);
    printf("result: %lf\n", result);
}
