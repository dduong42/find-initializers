#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

int main(int ac, char **av) {
    int ret = EXIT_SUCCESS;

    if (ac != 2) {
        fprintf(stderr, "Usage: find-initializers file\n");
        return EX_USAGE;
    }
    int fd = open(av[1], O_RDONLY);
    if (fd == -1) {
        perror("open");
        return EX_NOINPUT;
    }
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        return EX_OSERR;
    }
    void *addr = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        ret = EX_OSERR;
        goto clean_close;
    }
    /* Check that we're working with a Mach-O 64-bit file */
    struct mach_header_64 *header = addr;
    if (header->magic != MH_MAGIC_64) {
        fprintf(stderr, "Not a Mach-O 64-bit file\n");
        ret = EX_SOFTWARE;
        goto clean_munmap;
    }
    if (header->filetype != MH_DYLIB) {
        fprintf(stderr, "Not a shared library\n");
        ret = EX_SOFTWARE;
        goto clean_munmap;
    }

    struct symtab_command *symtab = 0;
    /* table of 32-bit offsets to initializers */
    uint32_t *inittable = 0;
    /* number of initializers */
    uint64_t ninit = 0;
    /* memory address of the __TEXT segment */
    uint64_t textaddr = 0;

    struct load_command *lc = addr + sizeof(*header);
    for (uint32_t ncmds = header->ncmds; ncmds; --ncmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segcmd = (struct segment_command_64 *) lc;
            struct section_64 *section = (void *) segcmd + sizeof(*segcmd);
            for (uint32_t nsects = segcmd->nsects; nsects; --nsects, ++section) {
                if ((section->flags & SECTION_TYPE) == S_INIT_FUNC_OFFSETS) {
                    textaddr = segcmd->vmaddr;
                    inittable = addr + section->offset;
                    ninit = section->size / sizeof(uint32_t);
                    break;
                }
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *) lc;
        }
        lc = (void *)lc + lc->cmdsize;
    }
    for (uint64_t i = 0; i < ninit; ++i) {
        struct nlist_64 *sym = addr + symtab->symoff;
        for (uint32_t nsyms = symtab->nsyms; nsyms; --nsyms, ++sym) {
            if (textaddr + inittable[i] == sym->n_value) {
                printf("0x%llx: %s\n", textaddr + inittable[i], (char *) addr + symtab->stroff + sym->n_un.n_strx);
                break;
            }
        }
    }
clean_munmap:
    munmap(addr, st.st_size);
clean_close:
    close(fd);
    return ret;
}
