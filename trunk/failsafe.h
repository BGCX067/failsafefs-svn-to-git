/*
  FailSafeFS:
  Copyright (C) 2009-2010  David Volgyes <david.volgyes@gmail.com>

  This program can be distributed under the terms of the GNU GPL2.
 */


#ifndef __FAILSAFE_LIB_HEADER__
#define __FAILSAFE_LIB_HEADER__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef DEBUG
#define debugMode true
#else
#define debugMode false
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
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

#include <iostream>

// Constants

/// Block size
#define FAILSAFE_BLOCK_SIZE 4096

/// Header size
#define FAILSAFE_HEADER_SIZE 256

/// Data block size
#define FAILSAFE_DATA_SIZE 3840
/// Hash size
#define HASH_SIZE 64

/// Hash method
#define HASH_METHOD GCRY_MD_SHA1

const int SUCCESS=0;
const int ERROR_SIGNATURE=1;
const int ERROR_VERSION=2;
const int ERROR_HASH=3;

/// Signature for FailSafeFS data block
static const char* FSSignature    ="FAILSAFE";
/// Signature for FailSafeFS description block
static const char* FSDescSignature="FAILDESC";

/// Version for FailSafeFS binary format
static const char* FSVersion      ="    1.00";

/*!
 *  FailSafe store struct for data
 *
 */
struct FailSafeStoreStruct {
		/// Signature
        char mSignature[8];
        /// Hash of the current block
        char mCurrentHash[HASH_SIZE];
        /// Version of the filesystem
        char mVersion[8];
        /// Data block counter (first block:0)
        int64_t mBlockCounter;
        /// Data offset from the beginning of the file
        int64_t mOffset;
        /// Size of data the current block ( 0..sizeof(data[]) )
        int64_t mSizeOfDataInCurrentBlock;
        /// Creation date of the current data block (in sec since Jan 1,1970)
        double mCreationDateOfCurrentBlock;
        /// Creation date of the first data block (in sec since Jan 1,1970)
        double mCreationDateOfFirstBlock;
        /// Hash of the previous block
        char mLastHash[HASH_SIZE];
        /// Revision number of the current block (for recovery purpose)
        int64_t mRevision;
        /// Random number vision number of the current block (for recovery purpose)
        char mRandomNumber[32];
        /// Reserved for future features
        char mReserved[32];
        /// Data
        char         data[3840];
} __attribute__((__packed__)) ;

/*!
 *  FailSafe desciption struct for metadata
 *
 */
struct FailSafeDescription {
		/// Signature
        char mSignature[8];

        /// Hash of the current block
        char mCurrentHash[HASH_SIZE];

        /// Version of the filesystem
        char mVersion[8];

        /// Data block counter (first block:0)
        int64_t mBlockCounter;

        /// Data offset from the beginning of the file
        int64_t mOffset;

        /// Size of data (path name) ( 0..sizeof(mLastPath[]) )
        int64_t mSizeOfDataInCurrentBlock;

        /// Creation date of the current data block (in sec since Jan 1,1970)
        double mCreationDateOfCurrentBlock;

        /// Creation date of the first data block (in sec since Jan 1,1970)
        double mCreationDateOfFirstBlock;

        /// Hash of the previous block
        char mLastHash[HASH_SIZE];

        /// Revision number of the current block (for recovery purpose)
        int64_t mRevision;

        /// Random number vision number of the current block (for recovery purpose)
        char mRandomNumber[32];

        /// User ID (UID)
        int64_t mUID;

        /// Group ID (GID)
        int64_t mGID;

        /// Permissions
        int64_t mPermissions;

        /// Is last path name full (0) or not(1)?
        char  mPartialPath;

        /// Last path name (for recovery purpose)
        char  mLastPath[3847];
} __attribute__((__packed__)) ;

/*!
	Random data generator

	@param destinationAddress destination memory address
	@param size length of random data

*/
inline void randomize(void* destinationAddress,unsigned int size)
{
        for (unsigned int p=0;p<size;++p) {
                unsigned char r= rand() % 256;
                reinterpret_cast<unsigned char*>(destinationAddress)[p]=r;
        }
}

/*!
 * hash calculation for data block
 * @param sourceStruct struct for HASH calculation
 */
inline void calculateHASH(FailSafeStoreStruct& sourceStruct)
{
        char* ptr=(reinterpret_cast<char*>(&sourceStruct))+sizeof(FailSafeStoreStruct::mSignature)+HASH_SIZE;
        int len=FAILSAFE_BLOCK_SIZE-(sizeof(FailSafeStoreStruct::mSignature)+HASH_SIZE);
        memset(sourceStruct.mCurrentHash,0,HASH_SIZE);
        gcry_md_hash_buffer( HASH_METHOD, sourceStruct.mCurrentHash, ptr,len );
}

/*!
 * hash calculation for description block
 * @param sourceStruct struct for HASH calculation
 */
inline void calculateDescHASH(FailSafeDescription& sourceStruct)
{
        char* ptr=(reinterpret_cast<char*>(&sourceStruct))+sizeof(FailSafeDescription::mSignature)+HASH_SIZE;
        int len=FAILSAFE_BLOCK_SIZE-(sizeof(FailSafeDescription::mSignature)+HASH_SIZE);
        memset(sourceStruct.mCurrentHash,0,HASH_SIZE);
        gcry_md_hash_buffer( HASH_METHOD, sourceStruct.mCurrentHash, ptr,len );
}

/*!
 * hash checking in data block
 * @param sourceStruct struct for HASH checking
 */
inline bool checkHASH(FailSafeStoreStruct& sourceStruct)
{
        char hash[HASH_SIZE];
        char* ptr=(reinterpret_cast<char*>(&sourceStruct))+sizeof(FailSafeStoreStruct::mSignature)+HASH_SIZE;
        int len=FAILSAFE_BLOCK_SIZE-(sizeof(FailSafeStoreStruct::mSignature)+HASH_SIZE);
        memset(hash,0,HASH_SIZE);
        gcry_md_hash_buffer( HASH_METHOD, hash, ptr,len );
        return memcmp(sourceStruct.mCurrentHash,hash,HASH_SIZE)==0;
}

/*!
 * hash checking in description block
 * @param sourceStruct struct for HASH checking
 */
inline bool checkDescHASH(FailSafeDescription& sourceStruct)
{
        char hash[HASH_SIZE];
        char* ptr=(reinterpret_cast<char*>(&sourceStruct))+sizeof(FailSafeDescription::mSignature)+HASH_SIZE;
        int len=FAILSAFE_BLOCK_SIZE-(sizeof(FailSafeDescription::mSignature)+HASH_SIZE);
        memset(hash,0,HASH_SIZE);
        gcry_md_hash_buffer( HASH_METHOD, hash, ptr,len );
        return memcmp(sourceStruct.mCurrentHash,hash,HASH_SIZE)==0;
}


/*!
 * checking data struct consistency
 * @param sourceStruct struct for consistency check
 * @return true, if check is successful
 */
inline bool checkConsistency(FailSafeStoreStruct& sourceStruct)
{
        bool result=true;
        if (!checkHASH(sourceStruct)) {
                result=false;
                if (debugMode)
                        std::cerr<<"block hash error"<<std::endl;
        }
        if (memcmp(sourceStruct.mSignature,FSSignature,sizeof(sourceStruct.mSignature))!=0) {
                result=false;
                if (debugMode)
                        std::cerr<<"block sign error"<<std::endl;
        }
        if (memcmp(sourceStruct.mVersion,FSVersion,sizeof(sourceStruct.mVersion))!=0) {
                result=false;
                if (debugMode)
                        std::cerr<<"block version error"<<std::endl;
        }
        return result;
}

/*!
 * checking data struct consistency
 * @param sourceStruct struct for consistency check
 * @return true, if check is successful
 */
inline bool checkDescConsistency(FailSafeDescription& sourceStruct)
{
        bool result=true;
        if (!checkDescHASH(sourceStruct)) {
                result=false;
                if (debugMode)
                        std::cerr<<"Desc hash error"<<std::endl;
        }
        if (memcmp(sourceStruct.mSignature,FSDescSignature,sizeof(sourceStruct.mSignature))!=0) {
                result=false;
                if (debugMode)
                        std::cerr<<"Desc sign error"<<std::endl;
        }
        if (memcmp(sourceStruct.mVersion,FSVersion,sizeof(sourceStruct.mVersion))!=0) {
                result=false;
                if (debugMode)
                        std::cerr<<"Desc vers error"<<std::endl;
        }
        return result;
}


inline void calculateHeader(FailSafeStoreStruct & dst,const FailSafeStoreStruct &lastblock,int64_t datasize,int64_t blockcounter, int64_t offset,int64_t revision)
{
        memcpy(dst.mSignature,FSSignature,sizeof(dst.mSignature));
        memcpy(dst.mVersion,FSVersion,sizeof(dst.mVersion));
        dst.mSizeOfDataInCurrentBlock=datasize;
        struct timeb tp;
        ftime(&tp);
        dst.mCreationDateOfCurrentBlock=tp.time+tp.millitm*0.001;
        dst.mBlockCounter=blockcounter;
        if (__builtin_expect(blockcounter==0,0)) {
                memset(dst.mLastHash,0,HASH_SIZE);
                // generate block_zero_creationdate
                dst.mCreationDateOfFirstBlock=dst.mCreationDateOfCurrentBlock;
                // generate random value
                randomize(&(dst.mRandomNumber),sizeof(dst.mRandomNumber));
        } else {
                memcpy(dst.mLastHash,lastblock.mCurrentHash,HASH_SIZE);
                memset(dst.mCurrentHash,0,HASH_SIZE);
                dst.mCreationDateOfFirstBlock=lastblock.mCreationDateOfFirstBlock;
                memcpy(dst.mRandomNumber,lastblock.mRandomNumber,32);
        }
        dst.mOffset=offset;
        dst.mRevision=revision;
        if (static_cast<int>(sizeof(dst.data))>datasize)
                memset(dst.data+datasize,0,sizeof(dst.data)-datasize);
        memset(dst.mReserved,0,sizeof(dst.mReserved));
}

inline void calculateDescription(FailSafeDescription& dst,const FailSafeStoreStruct &lastblock,std::string path,int64_t uid,int64_t gid,int64_t mode)
{
        memcpy(dst.mSignature,FSDescSignature,sizeof(dst.mSignature));
        memcpy(dst.mVersion,FSVersion,sizeof(dst.mVersion));
        struct timeb tp;
        ftime(&tp);
        dst.mCreationDateOfCurrentBlock=tp.time+tp.millitm*0.001;
        dst.mBlockCounter=lastblock.mBlockCounter+1;
        dst.mOffset=lastblock.mBlockCounter*FAILSAFE_DATA_SIZE+lastblock.mSizeOfDataInCurrentBlock;
        memcpy(dst.mLastHash,lastblock.mCurrentHash,HASH_SIZE);
        memset(dst.mCurrentHash,0,HASH_SIZE);
        dst.mCreationDateOfFirstBlock=lastblock.mCreationDateOfFirstBlock;
        memcpy(dst.mRandomNumber,lastblock.mRandomNumber,32);
        dst.mRevision=lastblock.mRevision+1;
        dst.mUID=uid;
        dst.mGID=gid;
        dst.mPermissions=mode;
        memset(dst.mLastPath,0,sizeof(dst.mLastPath));
        if (path.size()+1>sizeof(dst.mLastPath)) {
                path.erase(0,path.size()+1-sizeof(dst.mLastPath));
                dst.mPartialPath=1;
        } else {
                dst.mPartialPath=0;
        }
        strncpy(dst.mLastPath,path.c_str(),sizeof(dst.mLastPath));
        dst.mLastPath[sizeof(dst.mLastPath)-1]='\0';
        dst.mSizeOfDataInCurrentBlock=strlen(dst.mLastPath);
        calculateDescHASH(dst);
        checkDescConsistency(dst);
}

inline std::ostream& operator<<(std::ostream& dst,const FailSafeStoreStruct& src )
{
//  dst<<src.mSignature<<src.mVersion<<std::endl;
        dst<<"Block: "<<src.mBlockCounter<<std::endl;
        dst<<"Data : "<<src.mSizeOfDataInCurrentBlock<<std::endl;
        dst<<"Date of the first   data block: "<<src.mCreationDateOfFirstBlock<<std::endl;
        dst<<"Date of the current data block: "<<src.mCreationDateOfCurrentBlock<<std::endl;
        dst<<"Random ID: "<<src.mRandomNumber<<std::endl;
        dst<<"Revision : "<<src.mRevision<<std::endl;
        dst<<"Last    hash:"<<std::endl;
        for (int i=0;i<16;++i)
                dst<<std::hex<< static_cast<int>(src.mLastHash[i]) ;
        dst<<std::endl<<"Current hash:"<<std::endl;
        for (int i=0;i<16;++i)
                dst<<std::hex<<static_cast<int>(src.mCurrentHash[i]);
        dst<<std::endl;

        return dst;
}

inline std::ostream& operator<<(std::ostream& dst,const FailSafeDescription& src )
{
        if (src.mPartialPath)
                dst<<"Partial name:"<<src.mLastPath<<std::endl;
        else
                dst<<"Full name:"<<src.mLastPath<<std::endl;
        dst<<"Rev.:"<<src.mRevision<<std::endl;
        dst<<"Size:"<<src.mOffset<<std::endl;
        dst<<"Random ID: "<<src.mRandomNumber<<std::endl;
        dst<<"Current hash:"<<std::endl;
        for (int i=0;i<16;++i)
                dst<<std::hex<<static_cast<int>(src.mCurrentHash[i]);
        dst<<std::endl;
        return dst;
}

#endif
