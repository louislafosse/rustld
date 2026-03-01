#include <regex.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char* text = "alpha=42 beta=17 gamma=9001";
    regex_t re;
    if (regcomp(&re, "[a-z]+=[0-9]+", REG_EXTENDED) != 0) {
        return 20;
    }

    regmatch_t m;
    const char* p = text;
    int count = 0;
    while (regexec(&re, p, 1, &m, 0) == 0) {
        fwrite(p + m.rm_so, 1, (size_t)(m.rm_eo - m.rm_so), stdout);
        fputc('\n', stdout);
        p += m.rm_eo;
        count++;
    }

    regfree(&re);
    fprintf(stderr, "matches=%d len=%zu\n", count, strlen(text));
    return (count == 3) ? 0 : 21;
}
