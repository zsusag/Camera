/*******************************************************************************
 * Title: camera-update.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: July  1, 2016
 * Date Revised: August  3, 2016
 * Purpose: Add and/or remove files from a previously created encrypted backup.
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
#define _GNU_SOURCE
#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <search.h>
#include <argp.h>
#include "camera.h"
/* Declare and initialize the streamStructs which
   contain the variables needed to create and 
   maintain a string stream. The streamStruct for countStream
   is declared within main as there is no need for it
   to be a global variable */
streamStruct nonceStream, metadataStream, dirStream = {0};

/* Declare variables for the ultimate counts
   of the number of files and directories
   within the backup */
int finalMetadataCount;
int finalDirCount;
/* A comparison function used to
sort and find objects within the binary tree
which holds the metadata information for
the encrypted files */
int metadataTreeCmpFunc (const void * a, const void * b);
/* A walking function which goes through,
in order, each element of the metadata tree
and prints out the elements to the appropriate
files */
void walkHashTree(const void *data,VISIT x,int level);
/* A helper function which will maintain the contents
   of the binary trees. */
void databaseUpdater(FILE *fpInput, treeNode *treeData, void *treeHashMetadata,
                     char *backupDir, void *treeDir, bool del, bool verbose);
/* A walking function which goes through,
in order, each element of the directories
tree and prints out the elements and metadata
to the directories-map database file */
void walkDirTree(const void *data, VISIT x, int level);

int main(int argc, char *argv[])
{
  argumentsUpdate arguments;
  /* Default values for command line arguments */
  arguments.backupDir = NULL;
  arguments.modFile = NULL;
  arguments.delFile = NULL;
  arguments.silent = false;
  arguments.verbose = false;
  arguments.databaseDir = NULL;
  /* Parse the command line options and arguments */
  argp_parse(&argpUpdate, argc, argv, 0, 0, &arguments);

  /* 
     sodium_init initializes the Sodium library
     allowing for the functions within
     to work appropriately.
  */
  if (sodium_init() == -1) {
    return EXIT_FAILURE;
  }

  /*
    Prompt the user to enter, interactively, the secret key
    into the terminal window. The typed key will not 
    be echoed to the screen to prevent eavesdroppers from
    seeing the key. The key is then hashed and stored
    in its binary from as the actual key to be used for 
    future encryption.
  */
  unsigned char key[crypto_stream_chacha20_KEYBYTES];
  unsigned char dbNonce[crypto_stream_chacha20_NONCEBYTES];
  getpassSafe(key, dbNonce);

  /* If arguments.databaseDir is not equal to NULL,
     then the user wants unencrypted copies
     of the database files stored at a directory of their choosing.
     After removing any relative paths and extra '/' check to make
     sure that the directory exists. */
  if (arguments.databaseDir != NULL) {
    struct stat stDirTest = {0};
    if (stat(arguments.databaseDir, &stDirTest) == -1) {
      fprintf(stderr, "No directory under %s found.\n", arguments.databaseDir);
      return EXIT_FAILURE;
    }
  }

  /* Remove any extra '/' or relative paths from
     the given "backupDir". */
  arguments.backupDir = realpath(arguments.backupDir, NULL);

  /* These are the declarations
     of the files that will be used throughout the program.
     They are initlized to NULL before they are opened
     for initial reading or writing. */
  FILE *fpModFile = NULL;
  FILE *fpDelFile = NULL;

  /* Initialize the pathnames for
     the four database files. */
  FILE *fpDatabaseCount = NULL;
  FILE *fpDatabaseHashNonce = NULL;
  FILE *fpDatabaseHashMetadata = NULL;
  FILE *fpDatabaseDir = NULL;
 
  size_t cameraDirLen = strlen(arguments.backupDir) + strlen("/camera/");
  char cameraDir[cameraDirLen + 1];
  sodium_memzero(cameraDir, cameraDirLen);
  createOutputDirectory(cameraDir, arguments.backupDir, arguments.verbose, false);

  char dbHashNoncePath[cameraDirLen + strlen(HASH_NONCE_DB_NAME) + 1];
  char dbHashMetadataPath[cameraDirLen + strlen(HASH_METADATA_DB_NAME) + 1];
  char dbDirPath[cameraDirLen + strlen(DIRECTORIES_DB_NAME) + 1];
  char databaseCountPath[cameraDirLen + strlen(DATABASE_ENTRY_COUNT_NAME) + 1];

  sodium_memzero(dbHashNoncePath, sizeof(dbHashNoncePath));
  sodium_memzero(dbHashMetadataPath, sizeof(dbHashMetadataPath));
  sodium_memzero(dbDirPath, sizeof(dbDirPath));
  sodium_memzero(databaseCountPath, sizeof(databaseCountPath));

  /* Create the pathnames for the four database files. */
  constructDatabasePaths(cameraDir, cameraDirLen, dbHashNoncePath,
                         dbHashMetadataPath, dbDirPath, databaseCountPath);
  
  /* Open the database files for the "hashes-metadata",
     "hashes-nonces" and "database-count" for reading. If they
     cannot be opened, display a message to STDERR and exit immediately
     from the program. */
  openFile(&fpDatabaseHashNonce, dbHashNoncePath, "rb");
  openFile(&fpDatabaseHashMetadata, dbHashMetadataPath, "rb");
  openFile(&fpDatabaseDir, dbDirPath, "rb");
  openFile(&fpDatabaseCount, databaseCountPath, "rb");

  FILE *fpuDatabaseHashNonce = NULL;
  FILE *fpuDatabaseHashMetadata = NULL;
  FILE *fpuDatabaseCount = NULL;
  FILE *fpuDatabaseDir = NULL;

  /* If the user requested unencrypted copies
     of the database files, then construct the names of these files. */
  if (arguments.databaseDir != NULL) {

    size_t databaseDirLen = strlen(arguments.databaseDir);
    char uHashNoncePath[databaseDirLen +
                        strlen(HASH_NONCE_DB_NAME) + 1];
    char uHashMetadataPath[databaseDirLen +
                           strlen(HASH_METADATA_DB_NAME) + 1];
    char uDirPath[databaseDirLen +
                  strlen(DIRECTORIES_DB_NAME) + 1];
    char uDatabaseCountPath[databaseDirLen +
                            strlen(DATABASE_ENTRY_COUNT_NAME) + 1];
    
    sodium_memzero(uHashNoncePath, sizeof(uHashNoncePath));
    sodium_memzero(uHashMetadataPath, sizeof(uHashMetadataPath));
    sodium_memzero(uDirPath, sizeof(uDirPath));
    sodium_memzero(uDatabaseCountPath, sizeof(uDatabaseCountPath));

    constructDatabasePaths(arguments.databaseDir, databaseDirLen,
                           uHashNoncePath, uHashMetadataPath, uDirPath,
                           uDatabaseCountPath);
    
    openFile(&fpuDatabaseHashNonce, uHashNoncePath, "w");
    openFile(&fpuDatabaseHashMetadata, uHashMetadataPath, "w");
    openFile(&fpuDatabaseDir, uDirPath, "w");
    openFile(&fpuDatabaseCount, uDatabaseCountPath, "w");
  }
  /* Declare and initialize the remaining
     stream, countStream */
  streamStruct countStream = {0};
  /* Open the streams */
  metadataStream.stream = open_memstream(&metadataStream.string, &metadataStream.size);
  nonceStream.stream = open_memstream(&nonceStream.string, &nonceStream.size);
  dirStream.stream = open_memstream(&dirStream.string, &dirStream.size);
  countStream.stream = open_memstream(&countStream.string, &countStream.size);

  /* Decrypt the database files and store the decrypted data
     into the corresponding stream. */
  if (arguments.verbose) {
    printf("Decrypting database files ...\n");
  }
  chacha20_xor_file(fpDatabaseHashMetadata, metadataStream.stream, dbNonce,
                    key, true);
  chacha20_xor_file(fpDatabaseHashNonce, nonceStream.stream, dbNonce,
                    key, true);
  chacha20_xor_file(fpDatabaseCount, countStream.stream, dbNonce,
                    key, true);
  chacha20_xor_file(fpDatabaseDir, dirStream.stream, dbNonce,
                    key, true);
  /* Rewind all the streams so that the decrypted
     data can be read from them */
  rewindStreams(&metadataStream.stream, &nonceStream.stream,
                &dirStream.stream, &countStream.stream);
  
  /*
    Attempt to open the file containing the pathnames
    of the files that have either been modified
    or created for reading.
  */
  int counter = 0;
  int dirCounter = 0;
  if ( arguments.modFile != NULL) {
    if ( (fpModFile = fopen(arguments.modFile, "r")) == NULL) {
      fprintf(stderr, "%s cannot be opened as a readable file.\n", arguments.modFile);
      fprintf(stderr, "Exiting ... \n");
      return EXIT_FAILURE;
    }
    /* Count the number of entries
       within the ModFile */
    while(!feof(fpModFile)) {
      char ch = fgetc(fpModFile);
      if(ch == '\n')
        {
          counter++;
        }
    }
    rewind(fpModFile);
    dirCounter = counter;
  }
  dbEntry newlyEncryptedDb[counter];
  /*
    Continue to count how many entries
    are already within the metadata database file.
    "Counter" will be used to create the hash table
    which keeps track of the pathnames and their
    associated hash values as well as used to 
    declare another array of type "treeNode" which
    will contain all the information needed to create
    the updated database files.
  */
  char *buffer = NULL;
  readline(&buffer, countStream.stream);
  if (strncmp(buffer, "# OF ENTRIES", strlen("# OF ENTRIES")) != 0) {
    fprintf(stderr, "Entered wrong secret key.\nExiting...\n");
    return EXIT_FAILURE;
  }
  cryptoFree(buffer);
  readline(&buffer, countStream.stream);
  counter += strtol(buffer, NULL, 10);
  cryptoFree(buffer);
  if ( hcreate(counter * 1.3) == 0 ) {
    fprintf(stderr, "Error in creating hash table. This is most likely due to insufficient memory.\nExiting ...\n");
    return EXIT_FAILURE;
  }
  /*
    "treeData" is a the storage location for all
    of the data that is needed in order to create the metadata/hash
    and nonce/hash database files. The number of elements is "counter - 1"
    as the first line of the metadata/hash database file contains only information
    that is useful for the human user, describing what each column contains.

    "treeHashMetadata" is the initial root of the binary
    tree used to organize the data within "treeData". This value
    will be updated for subsequent rebalancing of the binary tree.
  */
  int treeDataSize = counter - 1;
  treeNode treeData[treeDataSize];
  /* bufferStorage will hold the pointers to the allocated
     strings that are produced by readline to be freed later. */
  char *bufferStorage[treeDataSize];
  sodium_memzero(treeData, sizeof(treeData));
  void *treeHashMetadata = NULL;
  counter = 0;
  
  /*
    Read in the current metadata database file line by line and store
    its contents in a the "treeHashMetadata" binary tree. This involves populating
    the entries of "treeData" as the binary tree only stores the pointers
    of data it is organizing, not copies.
  */
  while (readline(&buffer, metadataStream.stream) != -1) {
    /* 
       Because the first line of the metadata/hash database file
       is purely informational to the human user, the first
       line is ignored and immediately moves to the next line.
    */
    if (counter == 0) {
      counter++;
      cryptoFree(buffer);
      continue;
    }
    bufferStorage[counter - 1] = buffer;
    /*
      Populate the "counter - 1" entry of treeData using the data
      retrieved from the metadata/hash file.
    */
    treeNode *currentNode = &treeData[counter - 1];
    currentNode->index = counter - 1;
    strncpy(currentNode->hash, buffer, HASH_AS_HEX_SIZE);
    currentNode->hash[HASH_AS_HEX_SIZE] = '\0';
    currentNode->metadata = strchr(buffer, '\t') + 1;
    /*
      Add buffer to the binary tree. If tsearch
      returns NULL, a new entry had to be created but the program
      ran out of memory. In this circumstance, immediately
      exit from the program and report an error message.
    */
    if ( tsearch(currentNode, &treeHashMetadata, metadataTreeCmpFunc) == NULL) {
      fprintf(stderr, "Could not add entry to binary tree. Most likely due to insufficient memory. Exiting ...\n");
      return EXIT_FAILURE;
    }

    /*
      Add the pathname and hash of each entry in the metadata
      file in the hash table for quick and efficient retrieval
      in the future.
    */
    ENTRY htableEntry;
    htableEntry.key = (strrchr(currentNode->metadata, '\t') + 1);
    htableEntry.data = currentNode->hash;
    hsearch(htableEntry, (ACTION) ENTER);
    
    counter++;
  }
  cryptoFree(buffer);
  /*
    Count how many entries are in the directories database
    file and add that result onto the number of pathnames of files
    that have been modified or created since the last encrypted backup.
  */
  readline(&buffer, countStream.stream);
  dirCounter += strtol(buffer, NULL, 10);
  cryptoFree(buffer);
  /*
    Declare a storage location for all the information about the databases
    that will be subsequently organized by another binary tree. Additionally,
    declare and initialize the root of the new binary tree to be "treeDir".
    Lastly, reset the dirCounter to 0 for indexing purposes.
  */
  char *treeDirData[dirCounter];
  void *treeDir = NULL;
  dirCounter = 0;
  /*
    Read in the current directory database file and store its contents in 
    a binary tree for organization.
  */
  while (readline(&buffer, dirStream.stream) != -1) {
    if (strncmp(buffer, "INODE", 5) == 0) {
      cryptoFree(buffer);
      continue;
    }
    char *currentNode = treeDirData[dirCounter];
    currentNode = buffer;
    /*
      Add "buffer" to the binary tree. If tsearch
      returns NULL, a new entry had to be created but the program
      ran out of memory. In this circumstance, immediately
      exit from the program and report an error message.
    */
    if ( tsearch(currentNode, &treeDir, dirTreeCmpFunc) == NULL) {
      fprintf(stderr, "Could not add entry to binary tree. Most likely due to insufficient memory. Exiting ...\n");
      return EXIT_FAILURE;
    }
    dirCounter++;
  }
  cryptoFree(buffer);
  /* 
     Read in the current nonce database file and update the contents of the
     metadata/hash binary tree appropriately.
  */
  while (readline(&buffer, nonceStream.stream) != -1) {
    if (strncmp(buffer, "HASH", 4) == 0) {
      cryptoFree(buffer);
      continue;
    }
    treeNode currentNode;
    sodium_memzero(currentNode.hash, HASH_AS_HEX_SIZE + 1);
    strncpy(currentNode.hash, buffer, HASH_AS_HEX_SIZE);
    currentNode.metadata = NULL;
    /* 
       tfind will return a void * which is a pointer to a pointer
       to the data. The retrieved node will then have the nonce 
       field of the "treeNode" struct populated with the appropriate nonce.
    */
    treeNode **retrievedNode;
    if( (retrievedNode = tfind(&currentNode, &treeHashMetadata, metadataTreeCmpFunc)) == NULL ) {
      fprintf(stderr, "Could not find hash within tree when there should be entry.\nExiting...\n");
      cryptoFree(buffer);
      return EXIT_FAILURE;
    }
    treeNode *retrievedNodeData = *retrievedNode;
    /*
      The call the strncpy will copy in the data from the "buffer" from the
      last occurrence of the '\t' character, right before the nonce appears. Pointer
      arithmetic is done to make it so that the '\t' character is included
      as part of the nonce.
    */
    strncpy(retrievedNodeData->nonce, strrchr(buffer, '\t')+1, NONCE_AS_HEX_SIZE);
    cryptoFree(buffer);
  }
  cryptoFree(buffer);

  /*
    Open the file for reading that contains the list
    of pathnames of files that have been deleted from the system
    and thus need to be deleted from the encrypted database as well.
    Additionally, if the hash of the modified file was the only occurrence of that hash,
    delete the file from the encrypted directory.
  */
  if (arguments.delFile != NULL) {
    if ( (fpDelFile = fopen(arguments.delFile, "r")) == NULL) {
      fprintf(stderr, "%s cannot be opened as a readable file.\n", arguments.delFile);
      fprintf(stderr, "Exiting ... \n");
      return EXIT_FAILURE;
    }
    /*
      Update the binary trees, and thus, the databases,
      with the information of the deleted files. Additionally,
      if the hash of the deleted file was the only occurrence of that hash,
      delete the file from the encrypted directory.
    */
    databaseUpdater(fpDelFile, treeData, treeHashMetadata, arguments.backupDir, treeDir, true,
                    arguments.verbose);
  }
  /* 
     Create two temporary files: One which lists the files
     that were created and one that lists the files that 
     were modified.
  */
  unsigned int cursor = 0;
  FILE *fpCreatedFiles = tmpfile();
  FILE *fpModifiedFiles = tmpfile();
  if (arguments.modFile != NULL) {
    while (readline(&buffer, fpModFile) != -1) {
      if (buffer[strlen(buffer) - 1] == '/') {
        buffer[strlen(buffer) - 1] = '\0';
        char * dirCheck =  malloc(sizeof(char) * (INODE_LENGTH +
                                                  DEVICE_LENGTH +
                                                  MODE_LENGTH +
                                                  GUID_LENGTH +
                                                  UID_LENGTH +
                                                  ACCESSTIME_LENGTH +
                                                  MODTIME_LENGTH +
                                                  strlen(buffer) + 8)); 
        addDirToTree(buffer, dirCheck, &treeDir);
        cursor++;
        cryptoFree(buffer);
        continue;
      }
      ENTRY modFileEntry;
      modFileEntry.key = buffer;
      if ( hsearch(modFileEntry, (ACTION) FIND) == NULL ) {
        fprintf(fpCreatedFiles,"%s\n", buffer);
      }
      else {
        fprintf(fpModifiedFiles,"%s\n", buffer);
      }
      cryptoFree(buffer);
    }
    cryptoFree(buffer);
    rewind(fpCreatedFiles);
    rewind(fpModifiedFiles);
    /*
      Encrypt each file in the created temporary file, "fpCreatedFiles"
      and put them into the encrypted database. Then, update the cursor with the
      amount of files that were successfully encrypted.
    */
    if (arguments.verbose) {
      printf("Adding new files to backup ...\n");
    }
    cursor = hashAndEncrypt(arguments.backupDir, fpCreatedFiles, newlyEncryptedDb, key, 0, false, &treeDir, arguments.verbose, arguments.silent, counter);

    /* 
       Update the binary trees by removing previous
       information of the files that have been modified.
    */
    databaseUpdater(fpModifiedFiles, treeData, treeHashMetadata, arguments.backupDir, treeDir, false,
                    arguments.verbose);
  }
  
  /*
    Encrypt the files provided by "fpModifiedFiles" and place them into the
    encrypted database.
  */
  size_t tempCounter = counter;
  if (arguments.modFile != NULL) {
    rewind(fpModifiedFiles);
    if (arguments.verbose) {
      printf("Encrypting modified files ...\n");
    }
    cursor = hashAndEncrypt(arguments.backupDir, fpModifiedFiles, newlyEncryptedDb, key, cursor, false, &treeDir, arguments.verbose, arguments.silent, counter);
  
    /* Add new entries to database files */
    for (unsigned int i = 0; i < cursor; i++) {
      dbEntry *currentEntry = &newlyEncryptedDb[i];
      treeNode *currentNode = &treeData[counter];
      currentNode->index = counter;
      strncpy(currentNode->hash, currentEntry->hash, HASH_AS_HEX_SIZE);
      currentNode->hash[HASH_AS_HEX_SIZE] = '\0';
      strncpy(currentNode->nonce, currentEntry->nonce, NONCE_AS_HEX_SIZE);
      currentNode->nonce[NONCE_AS_HEX_SIZE] = '\0';
      size_t metadataStrLen = (INODE_LENGTH + DEVICE_LENGTH + MODE_LENGTH + GUID_LENGTH +
                               UID_LENGTH + ACCESSTIME_LENGTH + MODTIME_LENGTH + NUM_TAB_CHARS +
                               + strlen(currentEntry->pathname) + 1);
      char *metadata = malloc(sizeof(char) * metadataStrLen);
      snprintf(metadata, metadataStrLen ,"%u\t%d\t%o\t%d\t%d\t%d\t%d\t%s",
               (unsigned int) currentEntry->inode, (int) currentEntry->device,
               currentEntry->mode, currentEntry->uid,
               currentEntry->guid, (int) currentEntry->accessTime,(int)
               currentEntry->modTime, currentEntry->pathname);
      currentNode->metadata = currentEntry->pathname;
      if ( tsearch(currentNode, &treeHashMetadata, metadataTreeCmpFunc) == NULL) {
        fprintf(stderr, "Could not add entry to binary tree. Most likely due to insufficient memory. Exiting ...\n");
        return EXIT_FAILURE;
      }
      currentNode->metadata = metadata;
      ENTRY htableEntry;
      htableEntry.key = currentEntry->pathname;
      htableEntry.data = currentNode->hash;
      hsearch(htableEntry, (ACTION) ENTER);
      counter++;
    }
  }
  /* 
     Close the old versions of the metadata/hash and
     nonce/hash database files.
  */
  fclose(fpDatabaseHashNonce);
  fclose(fpDatabaseHashMetadata);
  fclose(fpDatabaseCount);
  fclose(fpDatabaseDir);
  /* Zero and free the old streams with the data from
     the previous data files and open new ones. */
  cleanupStreams(&metadataStream, &nonceStream, &dirStream, &countStream);
  metadataStream.string = NULL;
  nonceStream.string = NULL;
  dirStream.string = NULL;
  countStream.string = NULL;
  metadataStream.stream = open_memstream(&metadataStream.string, &metadataStream.size);
  nonceStream.stream = open_memstream(&nonceStream.string, &nonceStream.size);
  dirStream.stream = open_memstream(&dirStream.string, &dirStream.size);
  countStream.stream = open_memstream(&countStream.string, &countStream.size);
  /*
    Open new database files which will contain
    the updated information of the status of the 
    encrypted backup.
  */
  openFile(&fpDatabaseHashNonce, dbHashNoncePath, "wb");
  openFile(&fpDatabaseHashMetadata, dbHashMetadataPath, "wb");
  openFile(&fpDatabaseCount, databaseCountPath, "wb");
  openFile(&fpDatabaseDir, dbDirPath, "wb");
  /* Format the files for initial writing. */
  fprintf(metadataStream.stream, "HASH%28s\tINODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tPATHNAME\n", " ");
  fprintf(dirStream.stream, "INODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tDIRNAME\n");
  fprintf(nonceStream.stream, "HASH%28s\tNONCE\n", " ");
  fprintf(countStream.stream, "# OF ENTRIES\n");
  /*
    Walk through the binary trees, inorder, printing
    out the information to the appropriate
    database files along the way.
  */
  finalMetadataCount = 0;
  finalDirCount = 0;
  twalk(treeHashMetadata, walkHashTree);
  twalk(treeDir, walkDirTree);
  fprintf(countStream.stream, "%d\n%d\n", finalMetadataCount, finalDirCount);
  hdestroy();
  
  rewindStreams(&metadataStream.stream, &nonceStream.stream,
                &dirStream.stream, &countStream.stream);

  /* Write the encrypted database files
     out to the appropriate locations */
  if (arguments.verbose) {
    printf("Writing database files to %s\n", arguments.backupDir);
  }
  chacha20_xor_file(metadataStream.stream, fpDatabaseHashMetadata, dbNonce,
                    key, false);
  chacha20_xor_file(nonceStream.stream, fpDatabaseHashNonce, dbNonce,
                    key, false);
  chacha20_xor_file(countStream.stream, fpDatabaseCount, dbNonce,
                    key, false);
  chacha20_xor_file(dirStream.stream, fpDatabaseDir, dbNonce,
                    key, false);
  /* Create the unencrypted copies of the
     database files if the user specified an output
     directory for them */
  if (arguments.databaseDir != NULL) {
    if (arguments.verbose) {
      printf("Writing unencrypted database files to %s\n", arguments.databaseDir);
    }
    rewindStreams(&metadataStream.stream, &nonceStream.stream,
                  &dirStream.stream, &countStream.stream);
    createUnencryptedDb(metadataStream.stream, fpuDatabaseHashMetadata);
    createUnencryptedDb(nonceStream.stream, fpuDatabaseHashNonce);
    createUnencryptedDb(countStream.stream, fpuDatabaseCount);
    createUnencryptedDb(dirStream.stream, fpuDatabaseDir);
    fclose(fpuDatabaseHashMetadata);
    fclose(fpuDatabaseHashNonce);
    fclose(fpuDatabaseCount);
    fclose(fpuDatabaseDir);
  }
  /*
    Close all the remaining open files
    and free and zero all
    remaining allocated memory.
  */
  for (unsigned int i = 0; i < cursor; i++) {
    cryptoFree(newlyEncryptedDb[i].pathname);
  }
  for (int i = 0; i < treeDataSize; i++){
    free(bufferStorage[i]);
  }
  
  for (int i = tempCounter - 1; i < counter; i++) {
    free(treeData[i].metadata);
  }
  tdestroy(treeDir, free);
  sodium_memzero(key, sizeof(key));
  cleanupStreams(&metadataStream, &nonceStream, &dirStream, &countStream);
  free(arguments.backupDir);
  fclose(fpCreatedFiles);
  fclose(fpModifiedFiles);
  fclose(fpDatabaseHashNonce);
  fclose(fpDatabaseHashMetadata);
  fclose(fpDatabaseDir);
  fclose(fpDatabaseCount);
  if (arguments.modFile != NULL) {
    fclose(fpModFile);
  }
  if (arguments.delFile != NULL) {
    fclose(fpDelFile);
  }
  return EXIT_SUCCESS;
}


int metadataTreeCmpFunc (const void * a, const void * b) {
  treeNode *A = (treeNode *)a;
  treeNode *B = (treeNode *)b;
  
  if ( A->metadata == NULL || B->metadata == NULL ) {
    int answer;
    if ( (answer = strncmp(A->hash, B->hash, HASH_AS_HEX_SIZE)) == 0) {
      return answer;
    }
    else {
      return answer;
    }
  }
  char *pathA;
  char *pathB;

  if ( (pathA = strrchr(A->metadata, '\t')) == NULL)
    pathA = A->metadata;
  else
    pathA++;
  if ( (pathB = strrchr(B->metadata, '\t')) == NULL)
    pathB = B->metadata;
  else
    pathB++;

  size_t pathALen = strlen(pathA);
  size_t pathBLen = strlen(pathB);
  
  char compStrA[HASH_AS_HEX_SIZE + pathALen + 1];
  char compStrB[HASH_AS_HEX_SIZE + pathBLen + 1];

  sodium_memzero(compStrA, HASH_AS_HEX_SIZE + pathALen + 1);
  sodium_memzero(compStrB, HASH_AS_HEX_SIZE + pathBLen + 1);

  strncpy(compStrA, A->hash, HASH_AS_HEX_SIZE);
  strncpy(compStrB, B->hash, HASH_AS_HEX_SIZE);
  strncat(compStrA, pathA, pathALen);
  strncat(compStrB, pathB, pathBLen);
  if ( pathALen > pathBLen ) {
    return strncmp(compStrA, compStrB, HASH_AS_HEX_SIZE + pathALen );
  }
  else {
    return strncmp(compStrA, compStrB, HASH_AS_HEX_SIZE + pathBLen );
  }
}

void walkHashTree(const void *data,VISIT x,int level) {
  if (x == postorder || x == leaf) {
    treeNode *node= *(treeNode **)data;
    fprintf(metadataStream.stream, "%s\t%s\n", node->hash, node->metadata);
    if (node->nonce[0] != '\0') {
      fprintf(nonceStream.stream, "%s\t\t%s\n", node->hash, node->nonce);
    }
    finalMetadataCount++;
    sodium_memzero(node, sizeof(node));
    free(data);
  }
}

void walkDirTree(const void *data, VISIT x, int level) {
  if (x == postorder || x == leaf) {
    char *dir = *(char **)data;
    fprintf(dirStream.stream, "%s\n", dir);
    finalDirCount++;
  }
}

void databaseUpdater(FILE *fpInput, treeNode *treeData, void *treeHashMetadata, char *backupDir, void *treeDir, bool del, bool verbose) {
  char *buffer = NULL;
  while (readline(&buffer, fpInput) != -1) {
    if ((!del) && buffer[strlen(buffer) - 1] == '/') {
      cryptoFree(buffer);
      continue;
    }
    if (buffer[strlen(buffer) - 1] == '/' && del) {
      char checkDir[strlen(buffer) + 2]; // One for \t and one for \0
      checkDir[0] = '\t';
      strncat(checkDir, buffer, strlen(buffer));
      char *resultDir;
      if( (resultDir = tfind(checkDir, &treeDir, dirTreeCmpFunc)) == NULL ) {
        cryptoFree(buffer);
        continue;
      }
      char *resultDirConverted = *(char **)resultDir;
      if (verbose) {
        printf("Removing %s from database\n", buffer);
      }
      tdelete(resultDirConverted, &treeDir, dirTreeCmpFunc);
      cryptoFree(resultDir);
      cryptoFree(buffer);
      continue;
    }
    ENTRY hashToFind;
    hashToFind.key = buffer;
    ENTRY *retrievedHash;
    if( (retrievedHash = hsearch(hashToFind, (ACTION) FIND)) == NULL) {
      fprintf(stderr, "Could not retrieve hash for %s.\nExiting ...\n", buffer);
      cryptoFree(buffer);
      exit(EXIT_FAILURE);
    }
    treeNode fileNode;
    sodium_memzero(fileNode.hash, HASH_AS_HEX_SIZE + 1);
    strncpy(fileNode.hash, retrievedHash->data, HASH_AS_HEX_SIZE);
    fileNode.metadata = buffer;
    
    treeNode **resultHash;
    if( (resultHash = tfind(&fileNode, &treeHashMetadata, metadataTreeCmpFunc)) == NULL ) {
      fprintf(stderr, "Could not update database appropriately.\nExiting...\n");
      cryptoFree(buffer);
      exit(EXIT_FAILURE);
    }
    treeNode *retrievedNodeHash = *resultHash;
    int fileIndex = retrievedNodeHash->index;
    
    if ( treeData[fileIndex - 1].hash == retrievedNodeHash->hash ||
         treeData[fileIndex + 1].hash == retrievedNodeHash->hash) {
      free(retrievedNodeHash->metadata);
      if (verbose) {
        printf("Removing %s from database\n", retrievedNodeHash->hash);
      }
      tdelete(retrievedNodeHash, &treeHashMetadata, metadataTreeCmpFunc);
    }
    else {
      char encryptedFileName[DIRECTORY_PATH_LENGTH + strlen(backupDir) + strlen("/camera/") + 1];
      createEncryptedFileName(backupDir, encryptedFileName, retrievedNodeHash->hash);
      // Delete encrypted file
      if (verbose) {
        printf("Removing %s from backup \n", encryptedFileName);
      }
      unlink(encryptedFileName);
      // Delete entry from binary tree.
      if (verbose) {
        printf("Removing %s from database\n", encryptedFileName);
      }
      tdelete(retrievedNodeHash, &treeHashMetadata, metadataTreeCmpFunc);
    }
    cryptoFree(buffer);
  }
  cryptoFree(buffer);
}
