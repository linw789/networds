#include <stdio.h>
#include <stdlib.h>

#include "networds.h"

#if 0 
#define STRPOOL_IMPLEMENTATION
#include "strpool.h"
#endif

int main(int argc, char *argv)
{
    sit_test_registry_t::run();

#if 0
    FILE *file = 0;
    fopen_s(&file, "test.json", "r");
    if (file)
    {
        fseek(file, 0, SEEK_END);
        size_t file_length = ftell(file);
        fseek(file, 0, SEEK_SET);

        const size_t buffersize = 2014;
        char test_json_str[buffersize];
        test_json_str[buffersize - 1] = '\0';

        size_t file_read_length = fread(test_json_str, 1, file_length, file);
        if (file_length != file_read_length)
        {
            fprintf(stderr, "Failed to read the entire file\n");
        }
        fclose(file);

        networdpool_t wordspool;
        wordspool.words_count = 0;
        wordspool.pool_capacity = 10;
        wordspool.words = (netword_t *)malloc(wordspool.pool_capacity * sizeof(netword_t));

        strpool_t stringpool;
        strpool_init(&stringpool, 300, 20, 20);

        nw_json_read(test_json_str, file_read_length, &wordspool, &stringpool);

        char json_write_buffer[buffersize];
        nw_json_write(&wordspool, json_write_buffer, buffersize, &stringpool);

        fopen_s(&file, "test00.json", "w");
        if (file)
        {
            fprintf(file, json_write_buffer);
            fclose(file);
        }
    }
    else
    {
        fprintf(stderr, "Failed to open file\n");
    }
#endif

    nw_cmdl_run();

    return 0;
}
