#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
#pragma warning(disable: 4312)
#pragma warning(disable: 4477)
#pragma warning(disable: 4838)
// also had to turn off compiler option /Zc:wchar_t which makes wchar_t a built-in type instead of typedef
#define STB_DEFINE
#include "stb.h"
#pragma warning(pop)

#include "networds.h"

int main(int argc, char *argv)
{
    sit_test_registry_t::run();

    nw_cmdl_run();

    return 0;
}
