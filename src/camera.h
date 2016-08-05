/*******************************************************************************
 * Title: camera.h
 * Author(s): Zachary John Susag - Grinnell College
 * Date Created: June 30, 2016
 * Date Revised: August  5, 2016
 * Purpose: Serve as the header file for Camera
 *******************************************************************************
 * Copyright (C) 2016 Zachary John Susag
 * This file is part of Camera.
 * 
 * Camera is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * Camera is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with Camera; if not, see
 * <http://www.gnu.org/licenses/>.
 ******************************************************************************/
#ifndef CAMERA_H
#define CAMERA_H

#define _GNU_SOURCE
#define NONCE_BYTES crypto_stream_chacha20_NONCEBYTES
#define NONCE_AS_HEX_SIZE (NONCE_BYTES * 2)
#define HASH_BYTES 16
#define HASH_AS_HEX_SIZE (HASH_BYTES * 2)
#define RWX_OWNER_PERM 0700
#define SPLINTER_LENGTH 2
/* 3 for the three / present */
#define DIRECTORY_PATH_LENGTH HASH_AS_HEX_SIZE + 3 
#define BLOCK_SIZE 4096
#define INODE_LENGTH 9
#define DEVICE_LENGTH 2
#define MODE_LENGTH 6
#define GUID_LENGTH 3
#define UID_LENGTH 4
#define ACCESSTIME_LENGTH 10
#define MODTIME_LENGTH 10
#define NUM_TAB_CHARS 10

#include <stdlib.h>
#include <sys/types.h>

/* Names for the database files. Do NOT change if
   you have already constructed a backup using the default
   names as "camera-decrypt" will not be able to locate
   the files. */
static const char HASH_NONCE_DB_NAME[] = "hashes-nonces";
static const char HASH_METADATA_DB_NAME[] = "hashes-metadata";
static const char DIRECTORIES_DB_NAME[] = "directories-map";
static const char DATABASE_ENTRY_COUNT_NAME[] = "database-count";

extern struct argp argpInit;
/* Used by camera-init to communicate with parseOptInit. */
typedef struct {
  char **files;
  char *outputDir;
  bool silent, verbose;
  char *inputFile;
  char *databaseDir;
} argumentsInit;

extern struct argp argpDecrypt;
/* Used by camera-decrypt to communicate with parseOptDecrypt */
typedef struct {
  char *backupDir;
  char **files;
  char *outputDir;
  bool silent, verbose, all;
  char *inputFile;
} argumentsDecrypt;

extern struct argp argpUpdate;
/* Used by camera-update to communicate with parseOptUpdate */
typedef struct {
  char *backupDir;
  char *modFile;
  char *delFile;
  bool silent, verbose;
  char *databaseDir;
} argumentsUpdate;

/* This structure is used to store
   all of the metadata information about
   a file. */
typedef struct {
  char hash[HASH_AS_HEX_SIZE + 1];
  char nonce[NONCE_AS_HEX_SIZE + 1];
  ino_t inode;
  dev_t device;
  mode_t mode;
  uid_t uid;
  gid_t guid;
  time_t accessTime;
  time_t modTime;
  char *pathname;
  bool copy;
  int index;
  char *metadata;
} dbEntry;

/* This structure is used to store the information
   necessary to construct the binary tree
   within camera-update. */
typedef struct {
  char hash[HASH_AS_HEX_SIZE + 1];
  char *metadata;
  char nonce[NONCE_AS_HEX_SIZE + 1];
  int index;
} treeNode;

/* This structure used to store all the variables
   necessary to construct and maintain a string
   stream. This is used in each of the programs. */ 
typedef struct {
  char *string;
  FILE *stream;
  size_t size;
} streamStruct;
/* 
   This function takes in a string, the secret key, as keyString
   and computes its hash based upon the unsigned characters
   that correspond to the string. The hash, of size outLen, is then inserted
   into keyHash.
*/
void keyToHash(char *keyString, unsigned char *keyHash, size_t outLen);

/* 
   This function takes as inputs a full pathname, hashesDir,
   for the directory containing all the encrypted files,
   and hash, which is the result of hashing a particular (unencrypted) file.
   It constructs and returns the full pathname, outputDir, for
   the corresponding encrypted file.
*/
void createEncryptedFileName(char *outputDir, char *hashesDir, char *hash); 
/* 
   This function will xor the given file, fpInput, thus either encrypting it,
   or decrypting it, and storing the result in fpOutput. It will automatically
   keep track of the block counter and zero out the memory before completing
   fully.
*/
void chacha20_xor_file(FILE *fpInput, FILE *fpOutput,
                       unsigned char *nonce, unsigned char *key, bool decrypt);

/*
  This function will take in a path to an
  existing directory, "path", and recursively
  record the pathnames, one per line,
  of every file located in the directory
  into the file, "filesTBE".
*/

void fileFinder(char *path, FILE *filesTBE);

/*
  This function is mainly an extension of the 
  already present getline function from
  the GNU C library. Instead of recording
  the newline character at the end of a line
  it instead replaces the newline character
  with a null character. Otherwise,
  this function works nearly
  exactly the same as getline.
*/

ssize_t readline(char **lineptr,  FILE *stream);

/*
  This function has a dual purpose. First
  it will construct "hashesDirPath" by copying
  in "outputDir" and then concatenating
  "/hashes/" to the end of "hashesDirPath", thus
  creating the pathname of the "hashes" directory.
  Secondly, if the boolean value "init" is set to true
  then it will actually make the "hashes" directory
  along with all the subdirectories contained within.
*/

void createOutputDirectory(char *hashesDirPath, char *outputDir, bool verbose, bool init);

/*
  This function is a comparison function for use with
  the GNU C library host of sorting and searching functions,
  such as "qsort" and "bsearch". This specific function
  will compare two hashes contained within a 
  dbEntry struct and sort them in ascending,
  alphanumeric order.
*/

int hashSort (const void * a, const void * b);

/*
  This function will take the contents of
  "filesTBE" and hash them, producing the
  name of encrypted file,
  record the metadata information of both
  the file and the directory it is in, 
  and then encrypt the file using the ChaCha20
  stream cipher.
*/

unsigned int hashAndEncrypt(char *outputDir, FILE *filesTBE, dbEntry *database,
                            unsigned char *key, unsigned int cursor, bool init,
                            void **treeDir, bool verbose, bool silent, int fileCount);

/*
  This function will first
  turn off echoing to STDOUT and
  then prompt the user to enter in the secret
  key, which will then be stored within the program.
  After the key is stored, the terminal
  is restored to it's previous state with
  echoing turned on. Addiditionally, the nonce
will be created by hashing the key and the result
will be stored within nonce.
*/

ssize_t getpassSafe (unsigned char *key, unsigned char *nonce);

/*
  This function is a comparison function for use with
  the GNU C library host of sorting and searching functions.
  This particular function is used in conjunction with
  the binary trees present within camera-init and
  camera-update. It will take the end of a 
  string read in from one of the database files,
  move to the end of one of the lines and compare
  the pathnames of the two files, returning an integer.
*/

int dirTreeCmpFunc (const void *a, const void *b);

/*
  This function will compare the "hash" given
  with the hash of the the element in "database"
  at "index". If they are equal, then the
  "nonce" will be copied into the the
  corresponding field in the dbEntry struct and
  will call itself, incrementing the index,
  until it does not find a match.
*/ 

void nonceCopierNext(dbEntry *database, int index, char *hash, char *nonce);

/*
  This function will compare the "hash" given
  with the hash of the the element in "database"
  at "index". If they are equal, then the
  "nonce" will be copied into the the
  corresponding field in the dbEntry struct and
  will call itself, decrementing the index,
  until it does not find a match.
*/

void nonceCopierPrev(dbEntry *database, int index, char *hash, char *nonce);

/*
  This function will parse the information in "token",
  retrieved from one of the database files in camera-decrypt
  and store the parsed data into the appropriate
  field within "currentEntry". The boolean value
  "metadata" should be set to true if
  "token" is from the "hashes-metadata" file
  and false if it is from the "directories-map"
  file.
*/

void readInDatabase(dbEntry *currentEntry, char *token, bool metadata);

/*
  This function will take in a path to a 
  directory that will be created, "path",
  a path to an already present directory,
  "outputDir", the database of all the directories,
  "dirDb" and the size of said directory, "dirCounter".
  This function acts very much like "mkdir -p" in the bash shell
  as it will recursively create the directory showed to by "path"
  with "outputDir" prepended. It will also change the owner
  and permissions according to the entry within "dirDb". 
*/

int mkdir_p(char *path, char *outputDir, dbEntry *dirDb, size_t dirCounter, bool verbose);

/*
  This function is a helper function for 
  mkdir_p. It handles the actual searching for the
  appropriate entry within "dirDb" of the directory, creating
  the directory with the correct permissions, 
  and changing the owner of the newly created
  directory.
*/

void mkdir_pHelper(char *newPath, size_t outputDirLen, dbEntry *dirDb, size_t dirCounter, bool verbose);

/*
  This function takes in a path to a recently
  created directory, "path", the specified
  "outputDir", which will be prepended to "path",
  and an array of dbEntries that contains
  the metadata information about the directories. It will
  recursively go through and update the time stamps 
  of the directories according to the entry within
  "dirDb", which should be retrieved from the "directories-map"
  database file.
*/

void dirTimestampUpdater( char *path, char *outputDir, dbEntry *dirDb, size_t dirCounter);

/*
  This function will actually decrypt the file
  whose information is described within "metadataEntry"
  and place the newly decrypted file in "outputDir"
  according to the path name the file had
  when it was added to the backup directory,
  pointed to by "backupDir". The boolean value,
  "all", should be set to true if the entire
  backup is being decrypted.
*/

int decryptFile(dbEntry *metadataEntry, dbEntry *dirDb, char *backupDir, char *outputDir, unsigned char *key, bool all);

/*
  This function is essentially a cryptographically
  secure copying function which will copy the
  contents of a decrypted file into the path
  pointed to by the information found within
  "metadataEntry" with "outputDir" prepended to the
  front of the pathname. This function will also
  update the metadata of the newly copied file.
*/

int copyDecryptedFile(dbEntry *metadataEntry, char *inputFile, char *outputDir);

/*
  This function will update the metadata
  of a file whose pathname is given by
  "outputFilePath" with the information
  stored within "metadataEntry". Specifically,
  this function sets the owner, the group, the
  permissions, and the timestamps of the file.
*/

void updateFileMetadata(dbEntry *metadataEntry, char *outputFilePath);

/*
  This function will collect
  the metadata information given by
  "dirPath" and add a new entry to
  the binary tree pointed to by "treeDir".
*/

void addDirToTree(char *dirPath, char *dirCheck, void ** treeDir);

/*
  This function will construct the pathnames
  for each of the four database files
  used in camera. "dbHashNoncePath", "dbHashMetadataPath",
  "dbDirPath", and "databaseCountPath" all should have
  memory allocated beforehand as this function will only
  zero out the memory of each string and will copy and concatenate
  the strings as necessary.
*/

void constructDatabasePaths(char *hashesDir, size_t hashesDirLen, char *dbHashNoncePath,
                            char *dbHashMetadataPath, char *dbDirPath, char *databaseCountPath);

/*
  This function will attempt to open filePath
  as a FILE *, fp, and upon failure to open a
  error message will be displayed to STDERR and
  the program will immediately exit.
*/
void openFile(FILE **fp, char *filePath, char *mode);

/*
  This function will copy the contents of fpInput
  in blocks of size BLOCK_SIZE into fpOutput until
  fpInput and fpOutput are duplicates of each other.
*/
void createUnencryptedDb(FILE *fpInput, FILE *fpOutput);

/*
  This function will rewind each
  of the string streams to the beginning
  of the stream. This acts much the same
  way as any other file rewind.
*/
void rewindStreams(FILE **metadataStream, FILE **nonceStream,
                   FILE **dirStream, FILE **countStream);
/*
  This function will close each stream,
  zero out the strings that they created,
  and then freeing the memory that was allocated
  for those strings.
*/
void cleanupStreams(streamStruct *metadataStream, streamStruct *nonceStream,
                    streamStruct *dirStream, streamStruct *countStream);
/*
  This function will zero out
  the data, free data, and then
  set data equal to NULL. data
  should have been allocated using
  malloc or realloc in some way as free
  is called.
*/
void cryptoFree(void *data);

/*
  This function will determine whether
  pathname is a single file that the user
  would like to have the appropriate action
  done to it or if it is a directory. If it is a
  directory, then this function will call
  fileFinder to retrieve all of the files
  within said directory and place each file's path
  into outputFile, one per line.
*/
void collectFilesTBE(char *pathname, FILE *outputFile);

#endif
