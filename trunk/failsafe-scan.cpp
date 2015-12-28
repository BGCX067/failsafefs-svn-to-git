#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "failsafe.h"

/*#include <fuse.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <gcrypt.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
*/


int main(int argc,char*argv[])
{
        int res,fd;
        char storebuffer[FAILSAFE_BLOCK_SIZE*3];
        memset(storebuffer,0,FAILSAFE_BLOCK_SIZE*3);
        int64_t ptr=0;
        const int sign_length=strlen(FSDescSignature);
        char* sigPtr=0;

        if (argc!=2) {
                std::cerr<<argc<<" arguments!"<<std::endl;
                return 0;
        }

        fd = open(argv[1], O_RDWR);
        if (fd>0) {
                do {
                        memcpy(storebuffer,storebuffer+FAILSAFE_BLOCK_SIZE,FAILSAFE_BLOCK_SIZE);
                        res = pread(fd, storebuffer+FAILSAFE_BLOCK_SIZE, FAILSAFE_BLOCK_SIZE*2, ptr);
                        if ( (sigPtr=static_cast<char*>(memchr(static_cast<void *>(storebuffer+FAILSAFE_BLOCK_SIZE+1-sign_length), (FSDescSignature[0]),(FAILSAFE_BLOCK_SIZE-1+sign_length)))) && res) {
                                if (memcmp(sigPtr,FSDescSignature,sign_length)==0) {
                                        FailSafeDescription desc;
                                        memcpy(&desc,sigPtr,sizeof(FailSafeDescription));
                                        if (checkDescConsistency(desc)==true) {
                                                std::cout<<"Offset: "<<(ptr+static_cast<int64_t>(sigPtr-storebuffer)-FAILSAFE_BLOCK_SIZE)<<" Size: "<<desc.mOffset<<"Rev: "<<desc.mRevision<<" Name: "<<desc.mLastPath<<std::endl;
                                        }
                                }
                        }
                        ptr+=(res>FAILSAFE_BLOCK_SIZE?FAILSAFE_BLOCK_SIZE:res);
                } while (res>0);
                close(fd);
        }
        return 0;
}
