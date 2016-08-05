/*******************************************************************************
 * Title: camera-init.c
 * Author(s): Zachary John Susag - Grinnell College
 * Date Created: June 23, 2016
 * Date Revised: August  5, 2016
 * Purpose: The overarching purpose of this program is to initialize a "camera"
 *          directory which will serve as the encrypted, backup directory. The
 *          user provides a set of files, or directories, using the appropriate
 *          command line options which will then be used as a starting point
 *          for the encrypted directory. If the user provides a directory as an
 *          input, every file within that directory and all subdirectories will
 *          be used. Here is an overview of the steps the program takes to
 *          encrypt each file.
 *          * Parse the command line options.
 *          * Open the metadata files, overwriting files that currently exist.
 *          * Collect the full pathnames of the files and directories to be
 *            backed up.
 *          * Take the contents of each file and hash them, serving as the name
 *            of the encrypted file, collecting and storing the metadata in the
 *            appropriate data structures.
 *          * Encrypt each file using the ChaCha20 stream cipher, unless it
 *            would be redundant to do so.
 *          * Write the formatted metadata into plaintext streams.
 *          * Encrypt the metadata streams and write them to disk.
 *          * Clean up.
 *         It is important to note that this program does not check to see if
 *         there are contents within a "camera" directory other than the
 *         necessary subdirectories which are created within. Thus, multiple
 *         calls to this program will result in "snapshots" of the files that
 *         were desired to be backed up, rewriting the metadata files completely
 *         and possibly leaving remnants of previous backups (e.g. files that
 *         were deleted between the present and the last call to camera-init).
 *         
 *         For an incremental update to an already created directory, use
 *         camera-update.
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

/* dirCount is the count of the number of directories
   that the database files have metadata information for.
   dirStream is the plaintext stream that all data concerning the
   metadata information for the directories.
   The reasoning behind having these as global variables
   is that due to the implementation of binary trees in the
   GNU C library the "walking" function has to have a specific signature
   which disallows just passing in the variables as needed. */
unsigned int dirCount;
streamStruct dirStream;

/* This function is a helper function
   that walks the binary tree storing the
   directory metadata information and writes
   it to "fpDatabaseDir" */
void walkDirTree(const void *data, VISIT x, int level) {
  if (x == postorder || x == leaf) {
    char *str = *(char **)data;
    fprintf(dirStream.stream, "%s\n", str);
    dirCount++;
  }
}

int main(int argc, char *argv[])
{
  argumentsInit arguments;
  /* Default values for command line arguments */
  arguments.files = NULL;
  arguments.outputDir = NULL;
  arguments.silent = false;
  arguments.verbose = false;
  arguments.inputFile = NULL;
  arguments.databaseDir = NULL;
  /* Parse the command line options and arguments */
  argp_parse(&argpInit, argc, argv, 0, 0, &arguments);

  /* Initialize the Sodium library
     and exit immediately if it cannot
     be initialized. */
  if (sodium_init() == -1) {
    fprintf(stderr, "Sodium library could not be initialized\n");
    return EXIT_FAILURE;
  }
  /* Prompt the user to enter, interactively,
     the secret key used for encryption and decryption
     and store the hashed version within "key". During this,
     the nonce used to encrypt the database files will be created
     from the key. */
  unsigned char key[crypto_stream_chacha20_KEYBYTES];
  unsigned char dbNonce[crypto_stream_chacha20_NONCEBYTES];
  getpassSafe(key, dbNonce);
  
  /* Remove any extra '/' or relative paths from
     the given "outputDir" and databaseDir. */
  arguments.outputDir = realpath(arguments.outputDir, NULL);
  
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
  /* Create the output directory pathname */
  size_t cameraDirLen = strlen(arguments.outputDir) + strlen("/camera/");
  char cameraDir[cameraDirLen + 1];
  sodium_memzero(cameraDir, cameraDirLen + 1);
  createOutputDirectory(cameraDir, arguments.outputDir, arguments.verbose, true);
  
  /* Declare each file that will be either created or read
     from for the encryption process. */
  FILE *fpDatabaseHashNonce = NULL;
  FILE *fpDatabaseHashMetadata = NULL;
  FILE *fpDatabaseCount = NULL;
  FILE *fpDatabaseDir = NULL;
  /* Declare and allocate storage for the pathnames
     of each of the four database files */
  char dbHashNoncePath[cameraDirLen + strlen(HASH_NONCE_DB_NAME) + 1];
  char dbHashMetadataPath[cameraDirLen + strlen(HASH_METADATA_DB_NAME) + 1];
  char dbDirPath[cameraDirLen + strlen(DIRECTORIES_DB_NAME) + 1];
  char databaseCountPath[cameraDirLen + strlen(DATABASE_ENTRY_COUNT_NAME) + 1];

  /* Initally clear the memory of each pathname
     to prevent garbage data being present in the pathnames */
  sodium_memzero(dbHashNoncePath, sizeof(dbHashNoncePath));
  sodium_memzero(dbHashMetadataPath, sizeof(dbHashMetadataPath));
  sodium_memzero(dbDirPath, sizeof(dbDirPath));
  sodium_memzero(databaseCountPath, sizeof(databaseCountPath));

  /* Create the pathnames for the four database files. */
  constructDatabasePaths(cameraDir, cameraDirLen, dbHashNoncePath,
                         dbHashMetadataPath, dbDirPath, databaseCountPath);

  /* 
     Open the database files for all four of the databases for writing.
     If they cannot be opened, 
     for whatever reason, display a
     message to STDERR and exit immediately from the program.
  */
  openFile(&fpDatabaseHashNonce, dbHashNoncePath, "wb");
  openFile(&fpDatabaseHashMetadata, dbHashMetadataPath, "wb");
  openFile(&fpDatabaseDir, dbDirPath, "wb");
  openFile(&fpDatabaseCount, databaseCountPath, "wb");

  /* Declare the files that will store
     the unencrypted databases and initialize them to NULL. */
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
  /* Create a temporary file to contain
     a list of pathnames to be encrypted, one per line,
     from all of the sources available in camera-init. */
  size_t filesTBEPathLen = strlen("/tmp/cameraXXXXXX") + 1;
  char filesTBEPathname[filesTBEPathLen];
  sodium_memzero(filesTBEPathname, filesTBEPathLen);
  strncpy(filesTBEPathname, "/tmp/cameraXXXXXX", filesTBEPathLen);
  int fd = mkstemp(filesTBEPathname);
  FILE *filesTBE = fdopen(fd, "w+");
  int fileCount = 0;
  /* If the user provided pathnames
     to files on the command line, then add
     these to "filesTBE". */
  if (arguments.files != NULL) {
    for (int i = 0; arguments.files[i]; i++) {
      /* If the user wants to encrypt an entire directory,
         then call the function "fileFinder" to recursively
         add the pathnames of the files within "inputDir" and
         its subdirectories to "filesTBE" */
      collectFilesTBE(arguments.files[i], filesTBE);
    }
  }
  /* If the user provided a file which
     contains a list of pathnames of files
     they wish to have encrypted then copy these
     pathnames into "filesTBE" */
  if (arguments.inputFile != NULL) {
    FILE *fpInput = NULL;
    if ( (fpInput = fopen(arguments.inputFile, "r")) == NULL) {
      fprintf(stderr, "%s can't be opened as a readable file.\nExiting...\n",
              arguments.inputFile);
      return EXIT_FAILURE;
    }
    char *buffer = NULL;
    while ( readline(&buffer, fpInput) != -1) {
      collectFilesTBE(buffer, filesTBE);
    }
    cryptoFree(buffer, sizeof(buffer));
    fclose(fpInput);
  }
  /* Move back to the beginning of the file for reading. */
  rewind(filesTBE);

  /* Create the hash table to check for repeated hashes. */
  if ( hcreate((size_t) fileCount * 1.3) == 0 ) {
    fprintf(stderr, "Error in creating hash table. This is most likely due to insufficient memory.\nExiting ...\n");
    return EXIT_FAILURE;
  }
  /* Initalize the root of the binary tree
     which will store all of the metadata information
     about the directories containing the files
     being encrypted. */
  void *dirTree = NULL;

  char *uniqCommand = malloc((filesTBEPathLen * 2) + strlen("sort -u -o ") + 1);
  sodium_memzero(uniqCommand, sizeof(uniqCommand));
  sprintf(uniqCommand, "sort -u -o %s %s", filesTBEPathname, filesTBEPathname);
  system(uniqCommand);
  free(uniqCommand);
  /* Count how many lines are in
     filesTBE as this might have changed
     after duplicate entries are found and
     removed. */
  char ch;
  while(!feof(filesTBE)) {
    ch = fgetc(filesTBE);
    if (ch == '\n') {
      fileCount++;
    }
  }
  rewind(filesTBE);

  /* Storage location for all the metadata
     information about each file being encrypted */
  dbEntry hashDb[fileCount];
  /* Encrypt each file and write its entry
     into the "camera/" directory. First the function
     will hash the file which will be used as 
     the name of the encrypted file. Then the file will be
     encrypted  and stored within the camera directory. */
  unsigned int cursor = hashAndEncrypt(arguments.outputDir, filesTBE, hashDb, key, 0, true,
                                       &dirTree, arguments.verbose, arguments.silent, fileCount);
  /* Remove the hash table from the program. */
  hdestroy();

  /* Sort the "hashDb" in ascending, alphanumeric
     order according to the hash. */
  qsort(hashDb, (size_t) cursor, sizeof(dbEntry), hashSort);

  /* Declare the streamStructs for the remaining three
     database files. This structure contains all the variables
     needed to create and maintain a string stream. */
  streamStruct metadataStream, nonceStream, countStream = {0};

  /* Open the streams */
  metadataStream.stream = open_memstream(&metadataStream.string, &metadataStream.size);
  nonceStream.stream = open_memstream(&nonceStream.string, &nonceStream.size);
  dirStream.stream = open_memstream(&dirStream.string, &dirStream.size);
  countStream.stream = open_memstream(&countStream.string, &countStream.size);

  /* Format the files for initial wrtiting. */
  fprintf(metadataStream.stream, "HASH%28s\tINODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tPATHNAME\n", " ");
  fprintf(dirStream.stream, "INODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tDIRNAME\n");
  fprintf(nonceStream.stream, "HASH%28s\tNONCE\n", " ");
  fprintf(countStream.stream, "ENTRY TYPE\tNUMBER OF ENTRIES\n");
  
  /* For every entry within "hashDb", 
     print out the contents of the array
     to the appropriate streams. After
     the data has been copied and formatted
     into the different database files, zero the 
     entries and free the allocated memory.
  */
  for ( unsigned int i = 0; i < cursor; i++) {
    dbEntry *currentHashEntry = &hashDb[i];
    if ( currentHashEntry->copy == false ) {
      fprintf(nonceStream.stream, "%s\t%s\n",
              currentHashEntry->hash,
              currentHashEntry->nonce);
    }
    fprintf(metadataStream.stream, "%s\t%u\t%d\t%0o\t%d\t%d\t%d\t%d\t%s\n",
            currentHashEntry->hash, (unsigned int) currentHashEntry->inode,
            (int) currentHashEntry->device,
            currentHashEntry->mode, currentHashEntry->uid,
            currentHashEntry->guid, (int) currentHashEntry->accessTime,(int)
            currentHashEntry->modTime, currentHashEntry->pathname);
    /* Free the memory as the DB files are being written of each pathname. */
    cryptoFree(currentHashEntry->pathname, sizeof(currentHashEntry->pathname));
  }
  dirCount = 0;
  /* Walk through the binary
     tree containing the metadata on the
     directories in-order. During this walk-through
     the data will be formatted and printed
     to the dirStream. */
  twalk(dirTree, walkDirTree);

  /* Print the count of how many entries are
     within the "hashes-metadata" and
     "directories-map" database files. */
  fprintf(countStream.stream, "%s\t%d\n", "Hash metadata", cursor);
  fprintf(countStream.stream, "%s\t%d\n", "Directory count", dirCount);

  /* Rewind the streams before having the data
     read from them */
  rewindStreams(&metadataStream.stream, &nonceStream.stream,
                &dirStream.stream, &countStream.stream);

  /* Write the encrypted database files
     out to the appropriate locations */
  if (arguments.verbose) {
    printf("Writing database files to %s/camera\n", arguments.outputDir);
  }
  chacha20_xor_file(metadataStream.stream, fpDatabaseHashMetadata, dbNonce,
                    key, false);
  chacha20_xor_file(nonceStream.stream, fpDatabaseHashNonce, dbNonce,
                    key, false);
  chacha20_xor_file(countStream.stream, fpDatabaseCount, dbNonce,
                    key, false);
  chacha20_xor_file(dirStream.stream, fpDatabaseDir, dbNonce,
                    key, false);
  /* If the user requested that unencrypted copies of
     the database files were to be made, then rewind the streams again,
     copy the contents of the stream into the unencrypted database
     files and close the unencrypted database files */
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
  tdestroy(dirTree, free);
  /* Close the streams as they are no longer needed. */
  cleanupStreams(&metadataStream, &nonceStream, &dirStream, &countStream);
  /* Free any remaining allocated data 
     and close any remaining open files. */
  free(arguments.outputDir);
  remove(filesTBEPathname);
  fclose(filesTBE);
  fclose(fpDatabaseHashNonce);
  fclose(fpDatabaseHashMetadata);
  fclose(fpDatabaseDir);
  fclose(fpDatabaseCount);
  return EXIT_SUCCESS;
}
