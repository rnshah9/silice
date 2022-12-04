#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

namespace Silice
{
    class LuaPreProcessor;
    class ParsingContext;

    namespace Utils
    {
        int numLinesIn(std::string l);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    Silice::Utils::numLinesIn(str);

    return 0;
}