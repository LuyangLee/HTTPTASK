#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int main()
{
    // char uri[100];
    // char beforeuri[8] = {'h','t','t','p',':','/','/','\0'};
    // char data[9] = {'n','a','=','1','&','k','=','2','\0'};
    // size_t real_uri_size = sizeof(char) * 7;

    // snprintf(uri,real_uri_size,"%s?%s",beforeuri, data);
    // printf("%s", uri);
    FILE* f = fopen("./mytest/test.txt","r");
    if(f)
        printf("%d",1);
    return 0;
}
