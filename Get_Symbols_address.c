//
// Created by yt on 10/24/22.
//

#include <bfd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>



unsigned long Get_addr(char* s, char* argv) {
    long storage_needed, num_symbols, i;
    asymbol **symbol_table;
    bfd *abfd;
    char filename[100];

    bfd_init(); // magic

    abfd = bfd_openr(argv, NULL);
    assert(abfd != NULL);
    bfd_check_format(abfd, bfd_object);
    storage_needed = bfd_get_symtab_upper_bound(abfd);
    assert(storage_needed >= 0);
    symbol_table = (asymbol**)malloc(storage_needed);
    assert(symbol_table != 0);
    num_symbols = bfd_canonicalize_symtab(abfd, symbol_table);
    assert(num_symbols >= 0);
    for(i = 0; i < num_symbols; i++) {
        if (!strcmp(s, bfd_asymbol_name(symbol_table[i]))) {
            return bfd_asymbol_value(symbol_table[i]);
        }
    }
    return -1;
}
