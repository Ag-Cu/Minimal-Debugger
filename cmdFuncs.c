#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/user.h>
#include <Zydis/Zydis.h>
#include <inttypes.h>
#include "cmdFuncs.h"
#include "ast.h"
#include "Get_Symbols_address.h"

#define DATA_SIZE 10
extern const char *ARGV;

// A tedious but simple parsing function, parsing
// user input string into a command data structure.
 Cmd_t
parseCommand (char *s, int pid){
    char temp[1024];
    int i = 0;

    if (!s || !*s)
        return 0;

    // first get the command name, store it into "temp"
    while ((temp[i++]=*s++))
        if (*s==' ' || *s=='\0')
            break;

    temp[i] = '\0';

    if (0==strcmp (temp, "b")){
        long addr;
        if (!*(s)){
            printf ("break requires an address\n");
            return 0;
        }
        s++;
        if (*s == '0' && *(s+1) == 'x') {
            addr = strtol (s, 0, 0);
        } else {
            int symbols_addr = Get_addr(s, ARGV);
            if (symbols_addr == -1) {
                printf("No such symbol!\n");
                return 0;
            }
            addr = symbols_addr;
        }
        return Cmd_new_break (addr, pid);
    }
    else if (0==strcmp (temp, "c"))
        return Cmd_new_cont (pid);
    else if (0==strcmp (temp, "file")){
        if (!*s){
            printf ("file requires a file name\n");
            return 0;
        }
        return Cmd_new_file (s+1, pid);
    }
    else if (0==strcmp (temp, "q"))
        return Cmd_new_quit (pid);
    else if (0==strcmp (temp, "r"))
        return Cmd_new_run (pid);
    else if (0==strcmp (temp, "regs"))
        return Cmd_new_regs (pid);
    else if (0==strcmp (temp, "si"))
        return Cmd_new_si (pid);
    else if (0==strcmp (temp, "x/i")){
        long addr;
        if (!*(s)){
            printf ("x/i requires an address\n");
            return 0;
        }
        s++;
        if (*s == '0' && *(s+1) == 'x') {
            addr = strtol (s, 0, 0);
        } else {
            int symbols_addr = Get_addr(s, ARGV);
            if (symbols_addr == -1) {
                printf("No such symbol!\n");
                return 0;
            }
            addr = symbols_addr;
        }
        return Cmd_new_xi (addr, pid);
    }

    else if (0==strcmp (temp, "x/x")){
        long addr;
        if (!*(s)){
            printf ("x/x requires an address\n");
            return 0;
        }
        s++;
        if (*s == '0' && *(s+1) == 'x') {
            addr = strtol (s, 0, 0);
        } else {
            int symbols_addr = Get_addr(s, ARGV);
            if (symbols_addr == -1) {
                printf("No such symbol!\n");
                return 0;
            }
            addr = symbols_addr;
        }
        return Cmd_new_xx (addr, pid);
    }
    else;

    printf ("Unknown command: %s\n", temp);
    return 0;
}

// Given a command and execute it.
 void
execCommand (Cmd_t c){
    switch (c->kind){
        /*
         * Exercise 2 :
         * Now, how the breaking point command b 0xaddr is implemented?
         * In fact, there is a serious bug in current implementation we offered you.
         * Let's check where is this bug. First run this
         *      objdump -d hello
         * and figure out the address of the function print,
         * suppose that address is 0xaddr on your machine.
         * Now in the ssedb, you set up a break point on address 0xaddr
         * by typing (remember this address must be in hexadecimal, which has a leading 0x):
         *      (ssedb) b 0xaddr
         * now peek the registers:
         *      (ssedb) regs
         * What's the value of rip? Is this value right? Why?
         * And then disassembly the content at address 0xaddr.
         *      (ssedb) x/x 0xaddr
         * What's there? Have you detected the bug? How to fix this bug?
         */

        case CMD_KIND_BREAK:{
            /*
             * Todo("Exercise 2: Find out the bug in this case and fix it, submit your source code.")
             */
            long brk = 0x00000000000000cc;
            long data;
            long origin_data;
            struct user_regs_struct regs;

            data = ptrace(PTRACE_PEEKDATA, c->pid, c->u.addr, 0);
            origin_data = data;
            data = (data & 0xffffffffffffff00) | brk;
            ptrace(PTRACE_POKEDATA, c->pid, c->u.addr, data);
            ptrace(PTRACE_CONT, c->pid, 0, 0);

            waitChild ();

            ptrace(PTRACE_POKEDATA, c->pid, c->u.addr, origin_data);        // Restoring original data

            // Change rip register so that it will point to the right address
            memset(&regs, 0 ,sizeof(regs));
            ptrace (PTRACE_GETREGS, c->pid, 0, &regs);
            regs.rip = c->u.addr;
            ptrace (PTRACE_SETREGS, c->pid, 0, &regs);
            printf("->Set a breakpoint in 0x%x.\n", c->u.addr);
            return;
        }
        case CMD_KIND_CONT:{
            ptrace(PTRACE_CONT, c->pid, 0, 0);
            waitChild ();
            return;
        }
        case CMD_KIND_FILE:{
            kill (c->pid, SIGKILL);
            int pid = fork ();
            if (0==pid){
                ptrace (PTRACE_TRACEME, 0, 0, 0);
                execve (c->u.filename, &c->u.filename, 0);
            }
            else{
                waitChild ();
                printf ("loading: %s (pid: %d)\n", c->u.filename, pid);
                return;
            }
            return;
        }
        case CMD_KIND_QUIT:{
            int ch;
            L:
            printf ("ssedb is quiting. Are you sure? (y|n) ");
            ch = getchar ();
            if ('y'==ch || 'Y'==ch){
                kill (c->pid, SIGKILL);
                exit (0);
            }
            else if ('n'==ch || 'N'==ch){
                getchar ();
                return;
            }
            else {
                printf("\n");
                goto L;
            }
            return;
        }
        case CMD_KIND_REGS:{
            struct user_regs_struct regs;       // 用于存放子进程中寄存器的副本

            ptrace (PTRACE_GETREGS, c->pid, 0, &regs);      // 获取子进程中寄存器的值，并存放在regs中
            printf ("rax = %lld\n"
                    "rbx = %lld\n"
                    "rcx = %lld\n"
                    "rdx = %lld\n"
                    "rsi = %lld\n"
                    "rdi = %lld\n"
                    "rsp = 0x%p\n"              // 这三个寄存器中存放的都是地址
                    "rbp = 0x%p\n"
                    "rip = 0x%p\n",
                    regs.rax,
                    regs.rbx,
                    regs.rcx,
                    regs.rdx,
                    regs.rsi,
                    regs.rdi,
                    (char *)regs.rsp,
                    (char *)regs.rbp,
                    (char *)regs.rip);
            return;
        }
        case CMD_KIND_RUN:{
            ptrace(PTRACE_DETACH, c->pid, 0, 0);
            waitChild ();
            return;
        }
        case CMD_KIND_SI:{
            ptrace(PTRACE_SINGLESTEP, c->pid, 0, 0);
            return;
        }
        case CMD_KIND_XI:{
            /*
             * Exercise 3 :
             * There is also a command to disassembly bianry into assembly intructions,
             * but has not be completed. Now run
             *      (ssedb) x/i 0xaddr
             * you'll see an error message indicating the file position you should supply code.
             * Implement it. (Hint: manual disassemblying is tedious and error-prone,
             * so you may find some libraries are helpful, such as the zydis.)
             */

            /*
             * Todo("Exercise 3: Supply your code and Implement it.")
             */
            long buffer[DATA_SIZE];
            int i;
            long addr = c->u.addr;

            for (i=0; i<DATA_SIZE; i++){
                buffer[i] = ptrace(PTRACE_PEEKDATA, c->pid, addr, 0);
                addr += 8;
            }
            ZyanU8 data[8 * DATA_SIZE];
            memcpy(data, buffer, sizeof(buffer));
            // Initialize decoder context
            ZydisDecoder decoder;
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

            // Initialize formatter. Only required when you actually plan to do instruction
            // formatting ("disassembling")
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

            // Loop over the instructions in our buffer.
            // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
            // visualize relative addressing
            ZyanU64 runtime_address = c->u.addr;
            ZyanUSize offset = 0;
            const ZyanUSize length = sizeof(data);
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, length - offset,
                                                       &instruction, operands)))
            {
                // Print current instruction pointer.
                printf("%016" PRIX64 "  ", runtime_address);

                // Format & print the binary instruction structure to human-readable format
                char buffer[256];
                ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                                instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
                puts(buffer);

                offset += instruction.length;
                runtime_address += instruction.length;
            }
            /*
             * Challenge:
             * Another feature missing from the ssedb is debugging symbols.
             * For instance, when setting up breaking points,
             * we'd like just to type a symbolic name, such as:
             *      (ssedb) b main
             * instead of an ugly hexadecimal address for main.
             * Implement this feature.
             */

            return;
        }
        case CMD_KIND_XX:{
            // By default, we disassemble 40 bytes
            int i;
            long addr = c->u.addr;

            for (i=0; i<10; i++){
                long data = ptrace(PTRACE_PEEKDATA, c->pid, addr, 0);
                printf ("%lx: %lx\n", addr, data);
                addr += 8;
            }
            return;
        }
        default:
            printf ("Unknown command: ssedb bug!\n");
            return;
    }
}

 void
loopCommand (int pid){
    // buffer to hold user input, hopefully,
    // 1024 seems to be large enough.
    char buf[1024];

    while (1){
        printf ("(ssedb) ");
        gets(buf);

        Cmd_t c = parseCommand (buf, pid);
        // not a valid command, re-read
        if (!c)
            continue;

        // execute a valid command
        execCommand (c);
    }
}