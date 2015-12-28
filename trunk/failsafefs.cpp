/*
  FailSafeFS:
  Copyright (C) 2009-2010  David Volgyes <david.volgyes@gmail.com>

  This program can be distributed under the terms of the GNU GPL2.

  */

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "failsafe.h"
#include <cassert>
#include <map>
#include <pthread.h>

std::string basepath;

pthread_mutex_t globalMutex;

struct CacheStruct {
        bool hasDesc;
        FailSafeDescription desc;
        bool hasLastBlock;
        FailSafeStoreStruct lastblock;
        FailSafeStoreStruct lastwrittenblock;
        bool hasIncompleteBlock;
        FailSafeStoreStruct incompleteblock;
};

class Mutex
{
public:
        Mutex(pthread_mutex_t& mutex) :
                        mMutex(mutex) {
                lock();
        }

        ~Mutex() {
                unlock();
        }

        void lock() {
                pthread_mutex_lock( &mMutex );
        }

        void unlock() {
                pthread_mutex_unlock( &mMutex );
        }

private:
        pthread_mutex_t& mMutex;
};

std::map<int64_t,CacheStruct> cache;

static int fs_getattr(const char *path, struct stat *stbuf)
{
        std::string localpath=basepath+std::string(path);
        int res;
        int fd;
        FailSafeDescription desc;
        res = lstat(localpath.c_str(), stbuf);

        if ((res!=-1) && S_ISREG(stbuf->st_mode) && !S_ISDIR(stbuf->st_mode)) {
                fd = open(localpath.c_str(), O_RDONLY);
                if (fd == -1) {
                        return -errno;
                }
                if (stbuf->st_size>0 ) {
                        const int64_t blocks=stbuf->st_size/FAILSAFE_BLOCK_SIZE;
                        const int64_t reducedblocks=blocks>0?blocks-1:0;
                        res = pread(fd, &desc, sizeof(FailSafeDescription), reducedblocks*FAILSAFE_BLOCK_SIZE);
                        stbuf->st_size=desc.mOffset;
                        if (!checkDescConsistency(desc)) {
                                close(fd);
                                return -EIO;
                        }
                }
                close(fd);
        }
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_access(const char *path, int mask)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = access(localpath.c_str(), mask);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_readlink(const char *path, char *buf, size_t size)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = readlink(localpath.c_str(), buf, size - 1);
        if (res == -1)
                return -errno;

        buf[res] = '\0';
        return 0;
}


static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi)
{
        // TODO: mutex
        DIR *dp;
        Mutex mutex(globalMutex);
        struct dirent *de;
        std::string localpath=basepath+std::string(path);
        (void) offset;
        (void) fi;

        dp = opendir(localpath.c_str());
        if (dp == NULL)
                return -errno;

        while ((de = readdir(dp)) != NULL) {
                struct stat st;
                memset(&st, 0, sizeof(st));
                st.st_ino = de->d_ino;
                st.st_mode = de->d_type << 12;
                if (filler(buf, de->d_name, &st, 0))
                        break;
        }

        closedir(dp);
        return 0;
}

static int fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
        int res;
        std::string localpath=basepath+std::string(path);
        /* On Linux this could just be 'mknod(path, mode, rdev)' but this
           is more portable */
        if (S_ISREG(mode)) {
                res = open(localpath.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
                if (res >= 0)
                        res = close(res);
        } else if (S_ISFIFO(mode))
                res = mkfifo(localpath.c_str(), mode);
        else
                res = mknod(localpath.c_str(), mode, rdev);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_mkdir(const char *path, mode_t mode)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = mkdir(localpath.c_str(), mode);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_unlink(const char *path)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = unlink(localpath.c_str());
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_rmdir(const char *path)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = rmdir(localpath.c_str());
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_symlink(const char *from, const char *to)
{
        int res;
        std::string localfrom=basepath+std::string(from);
        std::string localto=basepath+std::string(to);

        res = symlink(localfrom.c_str(), localto.c_str());
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_rename(const char *from, const char *to)
{
        int res;
        std::string localfrom=basepath+std::string(from);
        std::string localto=basepath+std::string(to);

        res = rename(localfrom.c_str(), localto.c_str());
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_link(const char *from, const char *to)
{
        int res;
        std::string localfrom=basepath+std::string(from);
        std::string localto=basepath+std::string(to);

        res = link(localfrom.c_str(), localto.c_str());
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_chmod(const char *path, mode_t mode)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = chmod(localpath.c_str(), mode);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_chown(const char *path, uid_t uid, gid_t gid)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = lchown(localpath.c_str(), uid, gid);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_truncate(const char *path, off_t size)
{
        int res;

        std::string localpath=basepath+std::string(path);
        res = truncate(localpath.c_str(), size);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_utimens(const char *path, const struct timespec ts[2])
{
        std::string localpath=basepath+std::string(path);
        int res;
        struct timeval tv[2];

        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;

        res = utimes(localpath.c_str(), tv);
        if (res == -1)
                return -errno;

        return 0;
}

inline int readBlock(int fd,FailSafeStoreStruct & block, int64_t blockNr)
{
        int res=0;

        if (cache[fd].hasIncompleteBlock==true && (cache[fd].lastblock.mBlockCounter==blockNr)) {
                memcpy(&block,&(cache[fd].incompleteblock),sizeof(FailSafeStoreStruct));
                return 0;
        }

        if (cache[fd].hasLastBlock==true && (cache[fd].lastblock.mBlockCounter==blockNr)) {
                memcpy(&block,&(cache[fd].lastblock),sizeof(FailSafeStoreStruct));
        } else {
                res = pread(fd, &block, FAILSAFE_BLOCK_SIZE,blockNr*FAILSAFE_BLOCK_SIZE);
                if (res==-1)
                        return -errno;
                if (!checkConsistency(block)) {
                        return -EIO;
                }
        }

        return 0;
}

inline int writeBlock(int fd,FailSafeStoreStruct & block, int64_t blockNr)
{
        int res=0;

        if (cache[fd].hasIncompleteBlock==true && (cache[fd].lastblock.mBlockCounter!=blockNr)) {
                calculateHASH(cache[fd].incompleteblock);
                res = pwrite(fd, &(cache[fd].incompleteblock), FAILSAFE_BLOCK_SIZE,cache[fd].incompleteblock.mBlockCounter*FAILSAFE_BLOCK_SIZE);
                cache[fd].hasIncompleteBlock = false;
                if (res==-1)
                        return -errno;
        }

        if (block.mSizeOfDataInCurrentBlock==FAILSAFE_DATA_SIZE) {
                calculateHASH(block);
                res = pwrite(fd, &block, FAILSAFE_BLOCK_SIZE,blockNr*FAILSAFE_BLOCK_SIZE);
                if (res==-1)
                        return -errno;
                memcpy(&(cache[fd].lastwrittenblock),&block,sizeof(FailSafeStoreStruct));
        } else {
                memcpy(&(cache[fd].incompleteblock),&block,sizeof(FailSafeStoreStruct));
                cache[fd].hasIncompleteBlock=true;
        }
        return 0;
}

inline int flushBlock(int fd)
{
        if (cache[fd].hasIncompleteBlock==true) {
                int res = pwrite(fd, &(cache[fd].incompleteblock), FAILSAFE_BLOCK_SIZE,cache[fd].incompleteblock.mBlockCounter*FAILSAFE_BLOCK_SIZE);
                memcpy(&(cache[fd].lastwrittenblock),&(cache[fd].incompleteblock),sizeof(FailSafeStoreStruct));
                if (res==-1)
                        return -errno;
                cache[fd].hasIncompleteBlock=false;
                memcpy(&(cache[fd].lastblock),&(cache[fd].incompleteblock),sizeof(FailSafeStoreStruct));
                cache[fd].hasLastBlock=true;
        }
        return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
        Mutex mutex(globalMutex);
        int res;
        std::string localpath=basepath+std::string(path);
        int openflags=O_RDONLY;
        if ( fi->flags && O_WRONLY) openflags=O_RDWR;
        res = open(localpath.c_str(),openflags );
        if (res == -1) {
                return -errno;
        }
        fi->fh=res;
        CacheStruct cachedItem;
        cachedItem.hasDesc=false;
        cachedItem.hasLastBlock=false;
        cachedItem.hasIncompleteBlock=false;
        cache[res]=cachedItem;
        return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi)
{
        Mutex mutex(globalMutex);
        int fd=fi->fh;
        int res;

        int transfer;
        std::string localpath=basepath+std::string(path);
        FailSafeStoreStruct block;

        char *ptr=buf;
        int64_t localoffset=offset;

        int64_t remain;

        memset(buf,0,size);

        FailSafeDescription desc;
        struct stat stbuf;

        if (cache[fd].hasDesc==false) {
                lstat(localpath.c_str(), &stbuf);
                if (stbuf.st_size>FAILSAFE_BLOCK_SIZE) {
                        res = pread(fd, &desc, FAILSAFE_BLOCK_SIZE,stbuf.st_size-FAILSAFE_BLOCK_SIZE);
                        if (!checkDescConsistency(desc)) {
                                return -EIO;
                        }
                        if (res == -1) {
                                res = -errno;
                        }
                } else {
                        desc.mRevision=1;
                        desc.mOffset=0;
                }
                memcpy(&(cache[fd].desc),&desc,sizeof(desc));
                cache[fd].hasDesc=true;
        } else {
                desc.mRevision=cache[fd].desc.mRevision;
                desc.mOffset=cache[fd].desc.mOffset;
        }


        int64_t filesize=desc.mOffset;
        remain=(static_cast<int64_t>(offset+size)>filesize)?(filesize-offset):size;
        localoffset=offset;

        if (localoffset%FAILSAFE_DATA_SIZE!=0) {
                //read prev block
                res=0;
                int64_t blockNr=localoffset/FAILSAFE_DATA_SIZE;
                res=readBlock(fd,block,blockNr);
                if (res)
                        return res;

                // update block
                transfer=(remain>FAILSAFE_DATA_SIZE-(localoffset%FAILSAFE_DATA_SIZE))?(FAILSAFE_DATA_SIZE-(localoffset%FAILSAFE_DATA_SIZE)):remain;
                memcpy(ptr,block.data+(localoffset%FAILSAFE_DATA_SIZE),transfer);
                remain-=transfer;
                ptr+=transfer;
                localoffset+=transfer;
        }

        for (;remain>0;) {

                transfer=(remain>FAILSAFE_DATA_SIZE)?FAILSAFE_DATA_SIZE:remain;
                res=readBlock(fd,block,localoffset/FAILSAFE_DATA_SIZE);
                if (res)
                        return res;
                memcpy(ptr,block.data,transfer);
                remain-=transfer;
                ptr+=transfer;
                localoffset+=transfer;
        }
        return localoffset-offset;
}

static int fs_write(const char *path, const char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi)
{
        Mutex mutex(globalMutex);
        std::string localpath=basepath+std::string(path);
        int fd=fi->fh;
        int res=0;

        int transfer=0;
        int64_t revision=1;
        size_t remain=size;
        char *ptr=const_cast<char*>(buf);
        size_t localoffset=offset;
        FailSafeStoreStruct lastblock,block;
        FailSafeDescription desc;
        struct stat stbuf;

        memset(&block,0,sizeof(block));
        memset(&lastblock,0,sizeof(block));

        if (cache[fd].hasDesc==false) {
                if (lstat(localpath.c_str(), &stbuf)==0) {
                        if (stbuf.st_size>FAILSAFE_BLOCK_SIZE) {
                                res = pread(fd, &desc, sizeof(FailSafeDescription), stbuf.st_size-FAILSAFE_BLOCK_SIZE);
                                if (res == -1) {
                                        return -errno;
                                }
                                revision=desc.mRevision;
                        }
                } else {
                        return -errno;
                }
                memcpy(&(cache[fd].desc),&desc,sizeof(desc));
                cache[fd].hasDesc=true;
        } else {
                revision=cache[fd].desc.mRevision;
        }

        localoffset=offset;

        size_t localoffset_mod_data=localoffset%FAILSAFE_DATA_SIZE;
        size_t localoffset_div_datasize=localoffset/FAILSAFE_DATA_SIZE;
        if (localoffset_div_datasize>0 && localoffset_mod_data==0) {
                res=readBlock(fd,block,localoffset_div_datasize-1);
                if (res)
                        return res;
        }

        if (localoffset_mod_data!=0) {
                res=readBlock(fd,block,localoffset_div_datasize);
                if (res)
                        return res;

                transfer=(remain>FAILSAFE_DATA_SIZE-localoffset_mod_data)?(FAILSAFE_DATA_SIZE-localoffset_mod_data):remain;
                memcpy(block.data+localoffset_mod_data,ptr,transfer);
                calculateHeader(block,lastblock,transfer+(localoffset_mod_data),localoffset/FAILSAFE_DATA_SIZE, localoffset,revision);

                res=writeBlock(fd,block,localoffset_div_datasize);
                if (res)
                        return res;

                remain-=transfer;
                ptr+=transfer;
                localoffset+=transfer;
        }

        for (;remain>0;) {
                memcpy(&lastblock,&block,sizeof(block));
                transfer=(remain>FAILSAFE_DATA_SIZE)?FAILSAFE_DATA_SIZE:remain;
                //data
                memcpy(block.data,ptr,transfer);
                //header
                calculateHeader(block,lastblock,transfer+(localoffset_mod_data),localoffset/FAILSAFE_DATA_SIZE, localoffset,revision);
                //write out
                res=writeBlock(fd,block,localoffset/FAILSAFE_DATA_SIZE);
                if (res)
                        return res;
                remain-=transfer;
                ptr+=transfer;
                localoffset+=transfer;
        }
        return size;
}

static int fs_statfs(const char *path, struct statvfs *stbuf)
{
        int res;
        std::string localpath=basepath+std::string(path);
        res = statvfs(localpath.c_str(), stbuf);
        if (res == -1)
                return -errno;

        return 0;
}

static int fs_release(const char *path, struct fuse_file_info *fi)
{
        Mutex mutex(globalMutex);
        (void) path;
        int fd=fi->fh;
        if (fi->flags&O_WRONLY) {
                flushBlock(fi->fh);
                int res;
                std::string localpath=std::string(path);
                FailSafeDescription desc;
                struct stat stbuf;
                stat((basepath+localpath).c_str(),&stbuf);
                calculateDescription(desc,cache[fd].lastwrittenblock,localpath,stbuf.st_uid,stbuf.st_gid,stbuf.st_mode);

                res = pwrite(fd, &desc, FAILSAFE_BLOCK_SIZE, (cache[fd].lastwrittenblock.mBlockCounter+1)*FAILSAFE_BLOCK_SIZE);
                if (res == -1) {
                        return -errno;
                }
        }
        cache.erase(fi->fh);
        close(fi->fh);

        fi->fh=0;
        return 0;
}

static int fs_fsync(const char *path, int isdatasync,
                    struct fuse_file_info *fi)
{
        Mutex mutex(globalMutex);
        if (fi->flags & O_WRONLY)
                flushBlock(fi->fh);
        (void) path;
        (void) isdatasync;
        return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int fs_setxattr(const char *path, const char *name, const char *value,
                       size_t size, int flags)
{
        std::string localpath=basepath+std::string(path);
        int res = lsetxattr(localpath.c_str(), name, value, size, flags);
        if (res == -1)
                return -errno;
        return 0;
}

static int fs_getxattr(const char *path, const char *name, char *value,
                       size_t size)
{
        std::string localpath=basepath+std::string(path);
        int res = lgetxattr(localpath.c_str(), name, value, size);
        if (res == -1)
                return -errno;
        return res;
}

static int fs_listxattr(const char *path, char *list, size_t size)
{
        std::string localpath=basepath+std::string(path);
        int res = llistxattr(localpath.c_str(), list, size);
        if (res == -1)
                return -errno;
        return res;
}

static int fs_removexattr(const char *path, const char *name)
{
        std::string localpath=basepath+std::string(path);
        int res = lremovexattr(localpath.c_str(), name);
        if (res == -1)
                return -errno;
        return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations fs_oper;

int main(int argc, char *argv[])
{
        srand(static_cast<unsigned>(time(0)));
        fs_oper.getattr	 = fs_getattr;
        fs_oper.access	 = fs_access;
        fs_oper.readlink = fs_readlink;
        fs_oper.readdir	 = fs_readdir;
        fs_oper.mknod	 = fs_mknod;
        fs_oper.mkdir	 = fs_mkdir;
        fs_oper.symlink	 = fs_symlink;
        fs_oper.unlink	 = fs_unlink;
        fs_oper.rmdir	 = fs_rmdir;
        fs_oper.rename	 = fs_rename;
        fs_oper.link	 = fs_link;
        fs_oper.chmod	 = fs_chmod;
        fs_oper.chown	 = fs_chown;
        fs_oper.truncate = fs_truncate;
        fs_oper.utimens	 = fs_utimens;
        fs_oper.open	 = fs_open;
        fs_oper.read	 = fs_read;
        fs_oper.write	 = fs_write;
        fs_oper.statfs	 = fs_statfs;
        fs_oper.release	 = fs_release;
        fs_oper.fsync	 = fs_fsync;
#ifdef HAVE_SETXATTR
        fs_oper.setxattr     = fs_setxattr;
        fs_oper.getxattr     = fs_getxattr;
        fs_oper.listxattr    = fs_listxattr;
        fs_oper.removexattr  = fs_removexattr;
#endif

        globalMutex = PTHREAD_MUTEX_INITIALIZER;
        if ((sizeof(FailSafeStoreStruct)!=FAILSAFE_BLOCK_SIZE)||(sizeof(FailSafeDescription)!=FAILSAFE_BLOCK_SIZE)) {
                abort();
        }
        umask(0);

        // use first argument as source dir
        if (argc>2) {
                basepath=std::string(argv[1]);
                struct stat st;
                if ((stat(basepath.c_str(),&st) != 0) ||(!S_ISDIR(st.st_mode))) {
                        std::cerr<<"First parameter must be the source directory!"<<std::endl;
                        return 1;
                }
                return fuse_main(argc-1, argv+1, &fs_oper, NULL);
        } else {
                std::cerr<<"First parameter must be the source directory!"<<std::endl;
                std::cerr<<"Second parameter must be the mount point!"<<std::endl;
        }

        return 1;
}
