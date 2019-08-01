#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[], char *envp[])
{
    printf("------Show Command Line Arguments------\n");
    printf("The number of arguments: %d\n", argc - 1);

    for(int i = 1; i < argc; i++) {
        printf("[%d] %s\n", i, (char *)argv[i]);
    }

    printf("------Show Environment Variables \"SECRET\"------\n");
    const char* env_name = "SECRET=";
    int index = 0;
    while (envp[index]) {
        if (strncmp(env_name, envp[index], strlen(env_name)) == 0) {
            printf("%s\n", envp[index]);
            break;
        }
        ++index;
    }
    
    return 0;
}
