/*******************************************************************************
 * Title: camera-decrypt.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: June 30, 2016
 * Date Revised: August  5, 2016
 * Purpose: Decrypt files within an encrypted backup.
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

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <argp.h>
#include <errno.h>
#include <libgen.h>
#include <utime.h>
#include <search.h>
#include "camera.h"

int main(int argc, char *argv[])
{
  argumentsDecrypt arguments;
  /* Default values for command line arguments */
  arguments.files = NULL;
  arguments.outputDir = NULL;
  arguments.silent = false;
  arguments.verbose = false;
  arguments.all = false;
  arguments.inputFile = NULL;

  /* Parse all of the command line arguments and options */
  argp_parse(&argpDecrypt, argc, argv, 0, 0, &arguments); 

  /* Initalize the Sodium library */
  if (sodium_init() == -1) { 
    return EXIT_FAILURE; 
  } 

  /* Prompt the user to enter in their secret key interactively,
     hash it, and then store the hashed key as an unsigned char array */
  unsigned char key[crypto_stream_chacha20_KEYBYTES];
  unsigned char dbNonce[crypto_stream_chacha20_NONCEBYTES];
  getpassSafe(key, dbNonce); 

  /* If no outputDir was specified on the command line retrieve
     the current working directory and use that as default */
  if (arguments.outputDir == NULL) { 
    arguments.outputDir = getcwd(NULL, 0); 
  } 
  else { 
    arguments.outputDir = realpath(arguments.outputDir, NULL);
  }

  arguments.backupDir = realpath(arguments.backupDir, NULL);

  /* Create the name of the "camera/" directory */
  char cameraDir[strlen(arguments.backupDir) + strlen("/camera/") +
                 strlen(HASH_METADATA_DB_NAME) + strlen(HASH_NONCE_DB_NAME)];
  sodium_memzero(cameraDir, sizeof(cameraDir));
  createOutputDirectory(cameraDir, arguments.backupDir, arguments.verbose, false);
  size_t cameraDirLen = strlen(cameraDir);
  /*
    Declare each file that will be either created or read
    from for the encryption process.
  */
  FILE *fpDatabaseHashNonce = NULL;
  FILE *fpDatabaseHashMetadata = NULL;
  FILE *fpDatabaseDir = NULL;
  FILE *fpDatabaseCount = NULL;
  
  /* Create the pathnames for the four database files. */
  char dbHashNoncePath[cameraDirLen + strlen(HASH_NONCE_DB_NAME)];
  char dbHashMetadataPath[cameraDirLen + strlen(HASH_METADATA_DB_NAME)];
  char dbDirPath[cameraDirLen + strlen(DIRECTORIES_DB_NAME)];
  char databaseCountPath[cameraDirLen + strlen(DATABASE_ENTRY_COUNT_NAME) + 1];

  /* Using the Sodium library, zero out all four strings to prevent
     any random data from being present in the file names */
  sodium_memzero(dbHashNoncePath, sizeof(dbHashNoncePath));
  sodium_memzero(dbHashMetadataPath, sizeof(dbHashMetadataPath));
  sodium_memzero(dbDirPath, sizeof(dbDirPath));
  sodium_memzero(databaseCountPath, sizeof(databaseCountPath));

  constructDatabasePaths(cameraDir, cameraDirLen, dbHashNoncePath,
                         dbHashMetadataPath, dbDirPath, databaseCountPath);
  
  /* Open all four database files for reading and exit immediately
     if they cannot be opened */
  openFile(&fpDatabaseHashNonce, dbHashNoncePath, "rb");
  openFile(&fpDatabaseHashMetadata, dbHashMetadataPath, "rb");
  openFile(&fpDatabaseDir, dbDirPath, "rb");
  openFile(&fpDatabaseCount, databaseCountPath, "rb");

  /* Declare the variables needed to
     create and populate the memory streams which
     will serve as buffers
     between the unencrypted data and the
     decrypted data. */
  streamStruct metadataStream, nonceStream, dirStream, countStream = {0};
  /* Open the streams */
  metadataStream.stream = open_memstream(&metadataStream.string, &metadataStream.size);
  nonceStream.stream = open_memstream(&nonceStream.string, &nonceStream.size);
  dirStream.stream = open_memstream(&dirStream.string, &dirStream.size);
  countStream.stream = open_memstream(&countStream.string, &countStream.size);

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

  rewindStreams(&metadataStream.stream, &nonceStream.stream,
                &dirStream.stream, &countStream.stream);
  /* Retrieve the number of entries in the "hashes-metadata"
     file */
  char *countBuffer = NULL;
  readline(&countBuffer, countStream.stream);
  if (strncmp(countBuffer, "ENTRY TYPE", strlen("ENTRY TYPE")) != 0) {
    fprintf(stderr, "Entered wrong secret key.\nExiting...\n");
    cryptoFree(countBuffer);
    return EXIT_FAILURE;
  }
  cryptoFree(countBuffer);
  readline(&countBuffer, countStream.stream);
  char *countToken = strchr(countBuffer, '\t') + 1;
  size_t entryCounter = strtol(countToken, NULL, 10);
  cryptoFree(countBuffer);
  /* Create the hash table used to store each file's pathname
     and associated hash. Hash tables are most effective when they are
     only using up to 80% of their total storage. I'm being safe
     by allocating up to 130% of the needed storage size to
     maintain optimal performance */
  if ( hcreate(entryCounter * 1.3) == 0) {
    fprintf(stderr, "Error in creating hash table. This is most likely due to insufficient memory.\nExiting ...\n");
    return EXIT_FAILURE;
  }
  /* Initalize and zero the array which will
     contain all the parsed metadata information
     from the "hashes-metadata" file. */
  dbEntry metadataDb[entryCounter - 1];
  sodium_memzero(metadataDb, sizeof(metadataDb));

  /******************************************
   * PARSE & STORE DATABASE FILES IN MEMORY *
   ******************************************/

  /* Read in, line by line, each entry of the
     "hashes-metadata" file. Parse the data
     and store each piece into its respective location
     within the dbEntry structure. Also, add the
     pathname and hash into the hash table */
  entryCounter = 0;
  char *buffer = NULL;
  while ( readline(&buffer, metadataStream.stream) != -1) {
    if (entryCounter == 0) {
      entryCounter++;
      cryptoFree(buffer);
      continue;
    }
    dbEntry *currentEntry = &metadataDb[entryCounter - 1];
    currentEntry->metadata = buffer;
    currentEntry->index = entryCounter - 1;
    /* Convert all the data from the metadata file into 
       an array entry. */
    char *token = strtok(buffer, "\t");
    strncpy(currentEntry->hash, token, HASH_AS_HEX_SIZE);
    token = strtok(NULL,"\t");
    currentEntry->inode = (ino_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->device = (dev_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->mode = (mode_t) strtol(token, NULL, 8);
    token = strtok(NULL, "\t");
    currentEntry->uid = (uid_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->guid = (gid_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->accessTime = (time_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->modTime = (time_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentEntry->pathname = token;
    ENTRY htableEntry;
    htableEntry.key = currentEntry->pathname;
    htableEntry.data = currentEntry->hash;
    hsearch(htableEntry, (ACTION) ENTER);
    entryCounter++;
  }
  cryptoFree(buffer);
  /* Read in each line of the "hashes-nonces"
     file. Find each entry within "metadataDb" that
     corresponds to the hash and populate
     the nonce field within the structure for that item.
     Most likely there are copies of the same file within
     the backup. In this case one iteration will populate the nonce
     of all associated files with the same hash */
  while ( readline(&buffer, nonceStream.stream) != -1) {
    if (strncmp(buffer, "HASH", 4) == 0) {
      cryptoFree(buffer);
      continue;
    }
    char *token = strtok(buffer, "\t");
    char hashTemp[HASH_AS_HEX_SIZE + 1];
    strncpy(hashTemp, token, HASH_AS_HEX_SIZE);
    dbEntry check;
    strncpy(check.hash, hashTemp, HASH_AS_HEX_SIZE);

    token = strtok(NULL, "\t");
    dbEntry *retrievedEntry;
    if( (retrievedEntry = bsearch(&check, metadataDb, entryCounter - 1,
                                  sizeof(dbEntry), hashSort)) == NULL) {
      fprintf(stderr, "Could not add nonce to digital database from database file \
 on disk. This is a result of either insufficient memory or a corrupted database file.\n");
      fprintf(stderr, "Exiting ...\n");
      return EXIT_FAILURE;
    }
    strncpy(retrievedEntry->nonce, token, NONCE_AS_HEX_SIZE);
    nonceCopierNext(metadataDb, retrievedEntry->index + 1, retrievedEntry->hash, retrievedEntry->nonce);
    nonceCopierPrev(metadataDb, retrievedEntry->index - 1, retrievedEntry->hash, retrievedEntry->nonce);
    cryptoFree(buffer);
  }
  cryptoFree(buffer);
  /* Retrieve the number of entries within
     the directories database file */
  readline(&countBuffer,  countStream.stream);
  countToken = strchr(countBuffer, '\t') + 1;
  size_t dirCounter = strtol(countToken, NULL, 10);

  /* Zero out the buffer used to read in the data
     from the "database-count" file before freeing
     to prevent data leakage */
  cryptoFree(countBuffer);

  /* Declare a storage location to
     store in all the data
     from the "database-map" file */
  rewind(dirStream.stream);
  dbEntry dirDb[dirCounter];
  sodium_memzero(dirDb, sizeof(dirDb));
  dirCounter = 0;
  /* Read in the each line of the "database-map"
     file, line by line, and parse the information, 
     storing it within the appropriate locations
     within the dbEntry structure. */
  while ( readline(&buffer,  dirStream.stream) != -1) {
    if (dirCounter == 0) {
      dirCounter++;
      cryptoFree(buffer);
      continue;
    }
    dbEntry *currentDirEntry = &dirDb[dirCounter - 1];
    currentDirEntry->metadata = buffer;
    char *token = strtok(buffer, "\t");
    currentDirEntry->inode = (ino_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->device = (dev_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->mode = (mode_t) strtol(token, NULL, 8);
    token = strtok(NULL, "\t");
    currentDirEntry->uid = (uid_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->guid = (gid_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->accessTime = (time_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->modTime = (time_t) strtol(token, NULL, 10);
    token = strtok(NULL, "\t");
    currentDirEntry->pathname = token;
    dirCounter++;
  }
  cryptoFree(buffer);
  /****************************
   * ENTIRE BACKUP DECRYPTION *
   ****************************/
  
  /* If the "-a" option was given on the command line,
     for every directory in the "dirDb", as collected
     from the "directories-map" file,
     create the directory, restoring the appropriate
     owner, groups, and permissions */
  if(arguments.all) {
    for (int i = 0; i < dirCounter - 1; i++) {
      mkdir_p(dirDb[i].pathname, arguments.outputDir, dirDb, dirCounter, arguments.verbose);
    }
    /* Decrypt every file within "metadataDb", as
       collected from the "hashes-metadata" file. */
    int curIndex = 0;
    while (curIndex < entryCounter - 1) {
      curIndex = decryptFile(&metadataDb[curIndex], metadataDb, arguments.backupDir,
                             arguments.outputDir, key, true);
    }
    /* Update the time stamps for all the created
       directories after all the files have been created. */
    for (int i = 0; i < dirCounter - 1; i++) {
      dirTimestampUpdater(dirDb[i].pathname, arguments.outputDir, dirDb, dirCounter);
    }
  }
  /****************************
   * SINGULAR FILE DECRYPTION *
   ****************************/
  else {
    /* Create a temporary file
       to store the pathnames of all the files
       that need to be decrypted (TBD). */
    FILE *filesTBD = tmpfile();
    /* Store any files given on the command line
       into "filesTBD" */
    if (arguments.files != NULL) {
      for (int i = 0; arguments.files[i]; i++) {
        fprintf(filesTBD, "%s\n", arguments.files[i]);
      }
    }
    /* Copy all the files from an input file
       provided as a command line option, if supplied,
       into the "filesTBD" temporary file */
    if (arguments.inputFile != NULL) {
      FILE *fpInputList = NULL;
      if ( (fpInputList = fopen(arguments.inputFile, "r")) == NULL) {
        fprintf(stderr, "%s can't be opened as a readable file.\nExiting...\n",
                arguments.inputFile);
        return EXIT_FAILURE;
      }
      char *inputListBuffer = NULL;
      while (readline(&inputListBuffer, fpInputList) != -1) {
        fprintf(filesTBD, "%s\n", inputListBuffer);
      }
      sodium_memzero(inputListBuffer, sizeof(inputListBuffer));
      free(inputListBuffer);
      fclose(fpInputList);
    }
    rewind(filesTBD);

    /* For every file within "filesTBD", cut
       the directory the file is stored in and
       create, recursively, the directory. This
       will act like "mkdir -p" in the Shell. */
    while (readline(&buffer, filesTBD) != -1) {
      char pathCpy[strlen(buffer) + 1];
      strncpy(pathCpy, buffer, strlen(buffer));
      mkdir_p(dirname(pathCpy), arguments.outputDir, dirDb, dirCounter, arguments.verbose);
      cryptoFree(buffer);
    }
    cryptoFree(buffer);
    rewind(filesTBD);
    /* For every file within "filesTBD", 
       retrieve the hash associated with the
       pathname from the hash table, get the index
       of the file within the array using a binary search
       with the hash, and decrypt the file. As a part
       of the decryption process the owner
       and permissions of the file are restored
       to the state they were at the time the file was
       added to the backup. */
    while(readline(&buffer,  filesTBD) != -1) {
      ENTRY hashToFind;
      hashToFind.key = buffer;
      ENTRY *retrievedHash = NULL;
      if ( (retrievedHash = hsearch(hashToFind, (ACTION) FIND)) == NULL) {
        fprintf(stderr, "%s cannot be found within the current databases.\nContinuing...\n",
                buffer);
        continue;
      }
      dbEntry hashAsDbEntry;
      strncpy(hashAsDbEntry.hash, retrievedHash->data, HASH_AS_HEX_SIZE);
      dbEntry *retrievedEntry;
      if ( (retrievedEntry = bsearch(&hashAsDbEntry, metadataDb, entryCounter - 1,
                                     sizeof(dbEntry), hashSort)) == NULL) {
        fprintf(stderr, "Could not find %s in database.\nContinuing...\n",
                buffer);
        continue;
      }
      decryptFile(retrievedEntry, metadataDb, arguments.backupDir, arguments.outputDir, key, false);
      cryptoFree(buffer);
    }
    cryptoFree(buffer);
    rewind(filesTBD);
    /* Restore the time stamps for every directory that
       was created. */
    while (readline(&buffer, filesTBD) != -1) {
      dirTimestampUpdater(dirname(buffer), arguments.outputDir, dirDb, dirCounter);
      cryptoFree(buffer);
    }
    cryptoFree(buffer);
    fclose(filesTBD);
  }
  /* Zero out all of the memory that held
     sensitive information (key, anything that held
     data about the unencrypted files) before freeing
     the memory, either from a call to free or upon
     termination of the program. Destroy the hash
     table as well to prevent memory leakage. */
  for (unsigned int i = 0; i < entryCounter - 1; i++) {
    cryptoFree(metadataDb[i].metadata);
  }
  for (unsigned int i = 0; i < dirCounter - 1; i++) {
    cryptoFree(dirDb[i].metadata);
  }
  sodium_memzero(key, sizeof(key));
  sodium_memzero(buffer, sizeof(buffer));
  cleanupStreams(&metadataStream, &nonceStream, &dirStream, &countStream);
  entryCounter = 0;
  dirCounter = 0;
  hdestroy();
  if (!arguments.silent) {
    printf("Decryption of backup complete. Decrypted files can be found at %s\n",
           arguments.outputDir);
  }
  free(arguments.backupDir);
  cryptoFree(arguments.outputDir);
  return EXIT_SUCCESS;
}


