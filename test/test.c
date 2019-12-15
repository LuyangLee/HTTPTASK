#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#define DOWNLOADFILEHOME "./file/"
// #define DOWNLOADDIR "./file/"
int isfile(const char *filepath, char * tempname);
int main()
{
    // char uri[100];
    // char beforeuri[8] = {'h','t','t','p',':','/','/','\0'};
    // char data[9] = {'n','a','=','1','&','k','=','2','\0'};
    // size_t real_uri_size = sizeof(char) * 7;

    // snprintf(uri,real_uri_size,"%s?%s",beforeuri, data);
    // printf("%s", uri);
    char tempname[100];
    memset(tempname,'\0',100);
    strcat(tempname, DOWNLOADFILEHOME);
    int i = isfile("test.txt", tempname);
    printf("%d", i);
    return 0;

}

int isfile(const char *filepath, char * tempname)
{
    DIR *dir;
    struct dirent *d;
    if ((dir = opendir(tempname)) == NULL)
    {
        fprintf(stderr, "%s\n", "is not a dir");
        return -1;
    }
    while ((d = readdir(dir)))
    {
        if (0 == strcmp("..",d->d_name) || 0 == strcmp(".", d->d_name))
            continue;
        // printf("%d\n", d->d_type);
        // printf("%s\n", d->d_name);
        if (d->d_type == 8)
        {   
            strcat(tempname, d->d_name);
            if (0 == strcmp(tempname, filepath))
            {
                return 1;
            }
        }
        else if (d->d_type == 4)
        {
            
            strcat(tempname, d->d_name);
            strcat(tempname, "/");
            return isfile(tempname,tempname);
            
        }
        
    }
    // printf("%s\n",tempname );
    closedir(dir);
    return 0;
}