#include <stdio.h>
#include <stdlib.h>

#include "networds.h"

#if 0 
#define STRPOOL_IMPLEMENTATION
#include "strpool.h"
#endif

int main(int argc, char *argv)
{
#if 0
    char *jstr = NULL;
    lt_file *file = lt_file_open("test.json", LT_FILE_ACCESS::READ);
    int file_size = 0;
    if (file)
    {
        file_size = lt_file_size(file);
        jstr = (char *)malloc(file_size + 1);
        lt_file_read(file, jstr, file_size);
        jstr[file_size] = '\0';
    }
    lt_file_close(file);

    lt_json_token jtokens[100];
    int token_num = lt_json_tokenize(jstr, file_size, 0, 0);

    netword risible = nw_make("risible");

    nw_add_related_words(&risible, "laugh");
    nw_add_related_words(&risible, "funny");

    nw_output_json(&risible, 1);
#endif

#if 0
    strpool_config_t conf = strpool_default_config;
    //conf.ignore_case = true;

    strpool_t pool;
    strpool_init(&pool, &conf);

    STRPOOL_U64 str_a = strpool_inject(&pool, "This is a test string", (int)lt_str_length("This is a test string"));
    STRPOOL_U64 str_c = strpool_inject(&pool, "This is a test string", (int)lt_str_length("This is a test string"));
    STRPOOL_U64 str_b = strpool_inject(&pool, "THIS IS A TEST STRING", (int)lt_str_length("THIS IS A TEST STRING"));

    printf("%s\n", strpool_cstr(&pool, str_a));
    printf("%s\n", strpool_cstr(&pool, str_b));
    printf("%s\n", str_a == str_b ? "Strings are the same" : "Strings are different");
    unsigned int aa = 0;
    aa--;
    printf("uint-- : %x\n", aa);

    strpool_term(&pool);
#endif

#if 1
    NetwordsTests::run_tests();
#endif

    strpool astrpool;
    strpool_init(&astrpool, 1000, 100, 30);

    strpool_get_handle(&astrpool, "whatever", lt_str_length("whatever"));

    char pause = getchar();
    return 0;
}
