/*
  Source code of the Executable Pwn. The Executable will be
  called by the shellcode when the exploit succeed. This will
  create a file named "Pwn!" in the current directory.
*/

#include <stdio.h>

int main()
{
	FILE *f = fopen("Pwn!","w");
	close(f);
}
