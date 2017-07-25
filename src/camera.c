/*******************************************************************************
 * Title: camera.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: June 30, 2016
 * Date Revised: July 22, 2017
 * Purpose: Provide general functions for the Camera suite of programs.
 *******************************************************************************
 * Copyright (C) 2016,2017 Zachary John Susag
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
#include <termios.h>
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
#include <errno.h>
#include <libgen.h>
#include <utime.h>
#include "camera.h"

/* Purpose: Take the secret key, keyString, and convert each character
   into unsigned characters and then hash the key into outLen bytes, storing the
   result in keyHash.

   Preconditions: 
   * keyHash must have at least HASH_BYTES of memory allocated.
   * Refer to the libsodium documentation for specific conditions
     for the crypto_generichash function.

   TODO: Switch to password hashing function. */
void keyToHash(char *keyString, unsigned char *keyHash, size_t outLen) {
  
  size_t keyLen = strlen(keyString);
  unsigned char keyArray[keyLen];
  for ( unsigned int i = 0; i < keyLen; i++) {
    keyArray[i] = (unsigned char) keyString[i];
  }
  crypto_generichash(keyHash, outLen, keyArray, keyLen, NULL, 0);
}

/* Purpose: Create the full pathname for the encrypted file described
   by hash.

   Preconditions: 
   * Storage must be allocated for cameraDir beforehand and must have
     at least (strlen(outputDir) + HASH_AS_HEX_SIZE + 11) bytes.*/
void createEncryptedFileName(char *outputDir, char *cameraDir, char *hash) {
  strncpy(cameraDir, outputDir, strlen(outputDir));
  strncat(cameraDir, "/camera/", strlen("/camera/"));
  strncat(cameraDir, hash, SPLINTER_LENGTH);
  strncat(cameraDir, "/", 1);
  strncat(cameraDir, &hash[SPLINTER_LENGTH], SPLINTER_LENGTH);
  strncat(cameraDir, "/", 1);
  strncat(cameraDir, &hash[SPLINTER_LENGTH * 2], HASH_AS_HEX_SIZE - (SPLINTER_LENGTH * 2));
}

/* Purpose: Use the ChaCha20 stream cipher to xor fpInput and store the result
   in fpOutput.

   Preconditions:
   * fpInput must be opened for reading in binary.
   * fpOutput must be opened for writing in binary. */
void chacha20_xor_file(FILE *fpInput, FILE *fpOutput,
                       unsigned char *nonce, unsigned char *key,
                       bool decrypt) {
  size_t blockLength = 0;
  uint64_t blockCounter = 0;
  unsigned char block[BLOCK_SIZE] = {'\0'};
  unsigned char ciphertext[BLOCK_SIZE] = {'\0'};
  
  while ( (blockLength = fread(block, 1, BLOCK_SIZE, fpInput)) != 0) {
    crypto_stream_chacha20_xor_ic(ciphertext, block, blockLength,
                                  nonce, blockCounter, key);
    fwrite(ciphertext, 1, blockLength, fpOutput);
    blockCounter = blockCounter + (BLOCK_SIZE / 64);
    blockLength = 0;
  }
  sodium_memzero(decrypt ? ciphertext : block, BLOCK_SIZE);
}
/* Purpose: Compare two hashes stored within the dbEntry structure
   alphanumerically for use in the qsort procedure.

   Preconditions:
   * Meant to be called only through one of the GNU C library sorting functions. */
int hashCompare (const void * a, const void * b)
{
  dbEntry *A = (dbEntry *)a;
  dbEntry *B = (dbEntry *)b;

  for (unsigned int i = 0; i < HASH_BYTES; i++) {
    if (A->hash[i] != B->hash[i]) {
      return ( (int) A->hash[i] - B->hash[i] );
    }
  }
  return 0;
}

/* Purpose: For every file in the directory described by path, collect the
   pathnames for each file within path and all of its subdirectories
   and print the full pathname, one per line, into filesTBE.

   Preconditions:
   * path should point to a directory.
   * filesTBE is opened for writing.

   TODO: Rename fileFinder to a better name that's more informative */
void fileFinder(char *path, FILE *filesTBE) {
  DIR *dir;
  struct dirent *entry;
  if ((dir = opendir(path)) != NULL) {
    while (( entry = readdir(dir)) != NULL) {
      if (entry->d_type == DT_DIR &&
          strcmp(entry->d_name, ".") != 0 &&
          strcmp(entry->d_name, "..") != 0) {
        char newPath[strlen(path) + strlen(entry->d_name) + 2];
        sodium_memzero(newPath, sizeof(newPath));
        strncpy(newPath, path, strlen(path));
        if ( newPath[strlen(path) - 1] != '/' )
          newPath[strlen(path)] = '/';
        strncat(newPath, entry->d_name, strlen(entry->d_name));
        fileFinder(newPath, filesTBE);
      }
      else if (entry->d_type == DT_REG) {
        char *fullPath = realpath(path, NULL);
        fprintf(filesTBE, "%s/%s", fullPath, entry->d_name);
        fputc('\n', filesTBE);
        cryptoFree(fullPath, sizeof(fullPath));
      }
    }
  }
  closedir(dir);
}

/* Purpose: Read one entire line from stream and store the result
   in lineptr. Replace the newline character at the end of the
   line with a null character instead.

   Preconditions:
   * stream is opened for reading. */
ssize_t readline(char **lineptr, FILE *stream)
{
  size_t len = 0;
  ssize_t chars = getline(lineptr, &len, stream);

  if((*lineptr)[chars-1] == '\n') {
    (*lineptr)[chars-1] = '\0';
    --chars;
  }

  return chars;
}

/* Purpose: The main purpose of this function is to construct the full camera
   directory pathname from the given outputDir and store the result into
   cameraDirPath. The secondary purpose is that it will create the camera directory,
   and all subdirectories within, if init is set to true.

   Preconditions:
   * outputDir points to a directory.
   * cameraDirPath has memory allocated of at least (strlen(outputDir) + 9) bytes.
     - 8 for "/camera/" and 1 for the trailing null byte. */
void createOutputDirectory(char *cameraDirPath, char *outputDir, bool verbose, bool init) {
  /* 
     Append directory path with "/camera/" for correct directory
     to be made
  */
  
  strncpy(cameraDirPath, outputDir, strlen(outputDir));
  strncat(cameraDirPath, "/camera/", strlen("/camera/"));
  /*
    Check to see if directory already exists. If it does not,
    create the directory so that only the owner can access
    the files. The directory will be made in the user's current
    working directory.
  */
  if(init) {
    struct stat stCameraDirectoryTest = {0};
    if (stat(cameraDirPath, &stCameraDirectoryTest) == -1) {
      mkdir(cameraDirPath, RWX_OWNER_PERM);
      if(verbose) {
        printf("Creating directory \"camera\" at %s\n", cameraDirPath);
        printf("Creating subdirectories ...\n");
      }
      char hexChars[16] = "0123456789abcdef";
      // ab/de/ == 6 chars + '\0'
      size_t cameraDirPathLen = strlen(cameraDirPath);
      char subDirPath[cameraDirPathLen + 6 + 1];
      strncpy(subDirPath, cameraDirPath, cameraDirPathLen);
      subDirPath[cameraDirPathLen + SPLINTER_LENGTH] = '/';
      subDirPath[cameraDirPathLen + SPLINTER_LENGTH + 1] = '\0';
      for(int i = 0; i < 16; i++) {
        for( int j = 0; j < 16; j++) {
          subDirPath[cameraDirPathLen] = hexChars[i];
          subDirPath[cameraDirPathLen + 1] = hexChars[j];
          mkdir(subDirPath, RWX_OWNER_PERM);
        }
      }
      subDirPath[cameraDirPathLen + 5] = '/';
      subDirPath[cameraDirPathLen + 6] = '\0';
      for(int i = 0; i < 16; i++) {
        for( int j = 0; j < 16; j++) {
          for ( int k = 0; k < 16; k++) {
            for ( int l = 0; l < 16; l++) {
              subDirPath[cameraDirPathLen] = hexChars[i];
              subDirPath[cameraDirPathLen + 1] = hexChars[j];
              subDirPath[cameraDirPathLen + 3] = hexChars[k];
              subDirPath[cameraDirPathLen + 4] = hexChars[l];
              mkdir(subDirPath, RWX_OWNER_PERM);
            }
          }
        }
      }
    }
  }
}

/* Purpose: Read the contents of each file within filesTBE and generate a hash. Then encrypt
   the file, saving it in the camera directory which is inside outputDir.

   Preconditions:
   * filesTBE has a list of pathnames, one per line, of files to be encrypted as is readable.
   * treeDir is a pointer used for purpose of a binary tree. */
unsigned int hashAndEncrypt(char *outputDir, FILE *filesTBE, dbEntry *database,
                            unsigned char *key, unsigned int cursor, bool init,
                            void **treeDir, bool verbose, bool silent, int fileCount) {
  FILE * fpInput = NULL;
  FILE * fpOutput = NULL;
  
  // Declare block buffer for reading data in from fpInput.
  unsigned char block[BLOCK_SIZE] = {0};
  size_t blockLength = 0;

  /* 
     Declare variable to act as buffer from temporary file
     and opening of the file for binary read for subsequent
     encryption. The readline function will use realloc if
     the amount of space is too small for the line that is read in.
  */
  char *fileName = NULL;
  while (readline(&fileName, filesTBE) != -1) {
    // Check to see if the file can be opened as a readable-binary file.
    if ( (fpInput = fopen(fileName, "rb")) == NULL) {
      fprintf(stderr, "%s can't be opened as a readable-binary file.\n", fileName);
      cryptoFree(fileName, sizeof(fileName));
      continue;
    }

    /* 
       Create a pointer to the current index of the hashNonceDb
       for increased performance instead of having to
       index the array each time. The data collection/retrieval will
       be done using purely pointer arithmetic which results in a
       slightly more optimized runtime.
    */
    dbEntry *currentHashEntry = &database[cursor];

    /* 
       Create a buffer array to store the binary representation
       of the hash and nonce before converting them into their
       hexadecimal representations.
    */
    unsigned char binHash[HASH_BYTES];
    unsigned char binNonce[NONCE_BYTES];
    
    crypto_generichash_state state;
    crypto_generichash_init(&state, key, sizeof(key), sizeof(binHash));

    // Populate the nonce with random bytes.
    randombytes_buf(binNonce, sizeof(binNonce));

    /*
      Read in the file in blocks of BLOCK_SIZE bytes and update the hash with
      that block. Afterwards, set the memory of the block to zero
      and reset the blockLength to 0 in preparation for new
      block to be read in.
    */
    while( (blockLength = fread(block, 1, BLOCK_SIZE, fpInput)) != 0 ) {
      crypto_generichash_update(&state, block, blockLength);
      // Clean up after the hash has been updated.
      blockLength = 0;
    }
    sodium_memzero(block, blockLength);
    crypto_generichash_final(&state, binHash, sizeof(binHash));

    sodium_bin2hex(currentHashEntry->hash, HASH_AS_HEX_SIZE + 1, binHash, HASH_BYTES);
    
    sodium_bin2hex(currentHashEntry->nonce, NONCE_AS_HEX_SIZE + 1,
                   binNonce, NONCE_BYTES);
    /*
      Write the database entry that includes the hash value for each file,
      the mode, the inode number, the device containing the file, 
      the owners user ID, and the group ID in order
      to fully reconstruct the file to its original state before the
      encryption process.
    */
    char *fullPath = realpath(fileName, NULL);
    size_t dirPathLen = strlen(fullPath) - strlen(strrchr(fullPath, '/'));
    char dirPath[dirPathLen + 1];
    strncpy(dirPath, fullPath, dirPathLen);
    dirPath[dirPathLen] = '\0';
    char *dirCheck =  malloc(sizeof(char) * (INODE_LENGTH + DEVICE_LENGTH +
                                            MODE_LENGTH + GUID_LENGTH +
                                            UID_LENGTH + ACCESSTIME_LENGTH +
                                            MODTIME_LENGTH + dirPathLen + 8));
    addDirToTree(dirPath, dirCheck, treeDir);
    if (!silent && init && verbose) {
      printf("(%d/%d) Encrypting ... %s\n", cursor+1, fileCount, fullPath);
    }
    else if (!silent) {
      printf("Encrypting ... %s\n", fullPath);
    }
        
    struct stat inputAtt = {0};
    stat(fileName, &inputAtt);

    currentHashEntry->inode = inputAtt.st_ino;
    currentHashEntry->device = inputAtt.st_dev;
    currentHashEntry->mode = inputAtt.st_mode;
    currentHashEntry->uid = inputAtt.st_uid;
    currentHashEntry->guid = inputAtt.st_gid;
    currentHashEntry->copy = false;
    currentHashEntry->accessTime = inputAtt.st_atime;
    currentHashEntry->modTime = inputAtt.st_mtime;
    currentHashEntry->pathname = fullPath;

    int outputFileDirectoryLen = strlen(outputDir) + strlen("/camera/");
    /* 
       Create the outputFileName from the created hash. First, copy
       the current working directory into the string, concatenate with the
       "/camera" directory, convert the hash into a string hexadecimal representation
       using the sodium_bin2hex function, and concatenate that result
       onto the final string.
    */
    char outputFileName[DIRECTORY_PATH_LENGTH + outputFileDirectoryLen ]; 
    createEncryptedFileName(outputDir, outputFileName, currentHashEntry->hash);
    
    if (init) {
      ENTRY htableEntry;
      htableEntry.key = currentHashEntry->hash;
      if ( hsearch(htableEntry, (ACTION) FIND) != NULL ) {
        if (!silent) {
          printf("Copy of %s already exists. Skipping encryption ...\n", currentHashEntry->hash);
        }
        currentHashEntry->copy = true;
        cursor++;
        sodium_memzero(outputFileName, sizeof(outputFileName));
        fclose(fpInput);
        cryptoFree(fileName, sizeof(fileName));
        continue;
      }
      hsearch(htableEntry, (ACTION) ENTER);
    }

    if ( (fpOutput = fopen( outputFileName, "wb+")) == NULL) {
      if (!silent) {
        fprintf(stderr, "Output file can't be opened. Continuing ...\n");
      }
      cryptoFree(fileName, sizeof(fileName));
      continue;
    }

    // Go back to the beginning of the file
    rewind(fpInput);
    
    /*
      Read in blocks of BLOCK_SIZE bytes in length from the rewound input
      file. Then using the ChaCha20 stream cipher, encrypt the block
      using the generated nonce and key. Write the output to the
      outputFile and set the memory of the ciphertext to 0 in preparation
      for the next block. Also set the blockLength to zero for the same
      purpose and increment the blockCounter by (BLOCK_SIZE / 64).
    */
    chacha20_xor_file(fpInput, fpOutput, binNonce, key, false);
    
    /* 
       Close the input and output files before moving onto 
       the next file to be encrypted.
    */
    sodium_memzero(binHash, sizeof(binHash));
    sodium_memzero(binNonce, sizeof(binNonce));
    fclose(fpInput);
    fclose(fpOutput);
    cursor++;
    sodium_memzero(fileName, sizeof(fileName));
    free(fileName);
    fileName = NULL;
  }
  sodium_memzero(fileName, sizeof(fileName));
  free(fileName);
  fileName = NULL;
  return cursor;
}

/*
  Purpose: Turn off echoing to the current terminal, prompting the user
  to enter the secret key as a string. Once entered, restore the terminal.
*/
ssize_t getpassSafe(char *key) {
  struct termios old, new;
  int nread;
  /* Turn echoing off and fail if we can’t. */
  if (tcgetattr (fileno (stdin), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
    return -1;

  /* Read the password. */
  printf("Please enter the secret key: ");
  nread = readline (&key, stdin);
  putchar('\n');
  /* Restore terminal. */
  (void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
  return nread;
}

/* Purpose: Compare the pathnames stored at the end of two strings, a and b,
   alphabetically. Designed to be used for the tsearch function from the GNU
   C library. */
int dirTreeCmpFunc (const void *a, const void *b) {
  return strcmp( strrchr((char *)a, '\t') + 1, strrchr((char *)b, '\t') + 1);
}

/* Purpose: If the entries after index within database are of the same hash then
   copy nonce into the appropriate field within dbEntry.

   Preconditions:
   * index is less than or equal to one minus the total number of entries database
     can store. */
void nonceCopierNext(dbEntry *database, int index, char *hash, char *nonce) {
  dbEntry *currentEntry = &database[index];
  while ( strncmp(currentEntry->hash, hash, HASH_AS_HEX_SIZE) == 0 ) {
    strncpy(currentEntry->nonce, nonce, NONCE_AS_HEX_SIZE);
    currentEntry = &database[++index];
  }
}

/* Purpose: If the entries before index within database are of the same hash then
   copy nonce into the appropriate field within dbEntry.

   Preconditions:
   * index is greater than 0. */
void nonceCopierPrev(dbEntry *database, int index, char *hash, char *nonce) {
  dbEntry *currentEntry = &database[index];
  while ( strncmp(currentEntry->hash, hash, HASH_AS_HEX_SIZE) == 0) {
    strncpy(currentEntry->nonce, nonce, NONCE_AS_HEX_SIZE);
    currentEntry = &database[--index];
  }
}

/* Purpose: Parse the information found within token and store the data
   in the appropriate fields in currentEntry.

   Preconditions:
   * token should be generated by reading in a non-empty line from either the
     hashes-metadata or directories-map database files. Regardless, the data
     needs to be separated by tab characters. */
void readInDatabase(dbEntry *currentEntry, char *token, bool metadata) {
  if (metadata) {
    token = strtok(NULL,"\t");
  }
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
  if (metadata) {
    token = strtok(NULL,"\t");
  }
  token = strtok(NULL, "\t");
  currentEntry->pathname = token;
  printf("%s\t%u\t%d\t%o\t%d\t%d\t%d\t%d\t\t%s\n",
         currentEntry->hash, (unsigned int) currentEntry->inode,
         (int) currentEntry->device,
         currentEntry->mode, currentEntry->uid,
         currentEntry->guid, (int) currentEntry->accessTime,(int)
         currentEntry->modTime, currentEntry->pathname);
}

/* Purpose: Mimic the "mkdir -p" command from the bash shell.

   Preconditions:
   * path should point to a directory that needs to be created.
   * dirDb should have the necessary data needed to construct
     the directory structure.
   * outputDir should point to a directory. */
int mkdir_p(char *path, char *outputDir, dbEntry *dirDb,
            size_t dirCounter, bool verbose)
{
  size_t outputDirLen = strlen(outputDir); 
  char finalOutputDirPath[outputDirLen +
                          strlen(path) + 1];
  sodium_memzero(finalOutputDirPath, sizeof(finalOutputDirPath));
  strncpy(finalOutputDirPath, outputDir, outputDirLen);
  strncat(finalOutputDirPath, path, strlen(path));
  const size_t len = strlen(finalOutputDirPath);
  char newPath[PATH_MAX] = {'\0'};
  char *p;
  errno = 0;

  if (len > sizeof(newPath)-1) {
    fprintf(stderr, "Desired pathname is too long - %s.\n", path);
    exit(EXIT_FAILURE);
  }   
  strncpy(newPath, finalOutputDirPath, len);

  /* Iterate the string */
  for (p = &newPath[outputDirLen] + 1; *p; p++) {
    if (*p == '/') {
      /* Temporarily truncate */
      *p = '\0';
      mkdir_pHelper(newPath, outputDirLen, dirDb, dirCounter, verbose);
      *p = '/';
    }
  }
  mkdir_pHelper(newPath, outputDirLen, dirDb, dirCounter, verbose);
  return 0;
}

/* Purpose: Compare two pathnames found within the dbEntry structure alphanumerically.
   This function was designed to be used by the bsearch function from the GNU C library,
   hence the name. */
int bsearchDirCmpFunc(const void *a, const void *b) {
  dbEntry *A = (dbEntry *)a;
  dbEntry *B = (dbEntry *)b;

  return strcmp(A->pathname, B->pathname);
}

/* Purpose: Serve as a helper function to mkdir_p. Actually create the directories
   and update the permissions accordingly.

   Preconditions:
* The same preconditions hold here as they do for mkdir_p. */
void mkdir_pHelper(char *newPath, size_t outputDirLen, dbEntry *dirDb, size_t dirCounter, bool verbose) {
  dbEntry check;
  check.pathname = &newPath[outputDirLen];
  dbEntry *dirMetadata;
  if ( (dirMetadata = bsearch(&check, dirDb, dirCounter,
                              sizeof(dbEntry), bsearchDirCmpFunc)) == NULL) {
    if (mkdir(newPath, 0700) != 0) {
      if (errno != EEXIST) {
        fprintf(stderr, "Error occurred in creating directory, %s.\n",
                newPath);
        exit(EXIT_FAILURE); 
      }
    }
  }
  else {
    if (verbose) {
      printf("Creating directory: %s\n", newPath);
    }
    if (mkdir(newPath, dirMetadata->mode) != 0) {
      if (errno != EEXIST) {
        fprintf(stderr, "Error occurred in creating directory, %s.\n",
                newPath);
        exit(EXIT_FAILURE); 
      }
    }
    if (chown(newPath, dirMetadata->uid, dirMetadata->guid) != 0) {
      /*if (errno == EPERM) {
        fprintf(stderr, "Process does not have sufficient permissions to change \
        the owner of %s\n", newPath);
        }*/
    }
  }
}

/* Purpose: Update the access time and the modification time for all the directories
   found in path.

   Preconditions:
   * Both path and outputDir should point to directories.
   * dirCounter needs to be the number of entries within dirDb.
   * The process in which this function is called should have write permissions to the
     directory structure it is updating. */
void dirTimestampUpdater(char *path, char *outputDir, dbEntry *dirDb, size_t dirCounter) {
  size_t outputDirLen = strlen(outputDir); 
  char finalOutputDirPath[outputDirLen +
                          strlen(path) + 1];
  sodium_memzero(finalOutputDirPath, sizeof(finalOutputDirPath));
  strncpy(finalOutputDirPath, outputDir, outputDirLen);
  strncat(finalOutputDirPath, path, strlen(path));
  const size_t len = strlen(finalOutputDirPath);
  char newPath[PATH_MAX] = {'\0'};
  char *p;
  errno = 0;

  strncpy(newPath, finalOutputDirPath, len);

  dbEntry *dirMetadata;
  /* Iterate the string */
  for (p = &newPath[outputDirLen] + 1; *p; p++) {
    if (*p == '/') {
      /* Temporarily truncate */
      *p = '\0';
      dbEntry check;
      check.pathname = &newPath[outputDirLen];
      if ( (dirMetadata = bsearch(&check, dirDb, dirCounter,
                                  sizeof(dbEntry), bsearchDirCmpFunc)) != NULL) {
        struct utimbuf dirTime;
        dirTime.actime = dirMetadata->accessTime;
        dirTime.modtime = dirMetadata->modTime;
        if (utime(newPath, &dirTime) != 0) {
          if (errno == EACCES) {
            fprintf(stderr,
                    "Process does not have sufficient permissions to change "
                    "the timestamp of %s.\n",
                    newPath);
          }
          exit(EXIT_FAILURE);
        }
      }
      *p = '/';
    }
  }
  dbEntry check;
  check.pathname = &newPath[outputDirLen];
  if ( (dirMetadata = bsearch(&check, dirDb, dirCounter,
                              sizeof(dbEntry), bsearchDirCmpFunc)) != NULL) {
    struct utimbuf dirTime;
    dirTime.actime = dirMetadata->accessTime;
    dirTime.modtime = dirMetadata->modTime;
    if (utime(newPath, &dirTime) != 0) {
      if (errno == EACCES) {
        fprintf(stderr,
                "Process does not have sufficient permissions to change "
                "the timestamp of %s.\n",
                newPath);
      }
      exit(EXIT_FAILURE);
    }
  }
}
/* Purpose: Decrypt the file described by metadataEntry and store the decrypted copy into
   outputDir.

   Preconditions:
   * metadataEntry is not null.
   * backupDir points to the camera directory in which the encrypted copy is stored.
   * outputDir points to a directory in which the decrypted copy is to be stored.
   * key is crypto_stream_chacha20_KEYBYTES in size. */
int decryptFile(dbEntry *metadataEntry, dbEntry *dirDb, char *backupDir, char *outputDir, unsigned char *key, bool all) {
  size_t hashDirLen = strlen(backupDir);
  char hashFilePath[hashDirLen + strlen("/camera/") + DIRECTORY_PATH_LENGTH];
  sodium_memzero(hashFilePath, sizeof(hashFilePath));
  createEncryptedFileName(backupDir, hashFilePath,
                          metadataEntry->hash);
  char outputFilePath[strlen(outputDir) + strlen(metadataEntry->pathname) + 1];
  sodium_memzero(outputFilePath, sizeof(outputFilePath));
  strncpy(outputFilePath, outputDir, strlen(outputDir));
  strncat(outputFilePath, metadataEntry->pathname, strlen(metadataEntry->pathname));

  unsigned char nonce[NONCE_BYTES];
  size_t nonceLength;
  sodium_hex2bin(nonce, sizeof(nonce), metadataEntry->nonce, NONCE_AS_HEX_SIZE, NULL, &nonceLength, NULL);

  FILE *fpInput = NULL;
  FILE *fpOutput = NULL;

  if ( (fpInput = fopen(hashFilePath, "rb")) == NULL) {
    fprintf(stderr, "%s can't be opened as a readable-binary file.\n", hashFilePath);
    exit(EXIT_FAILURE);
  }
  
  if ( (fpOutput = fopen(outputFilePath, "wb+")) == NULL ) {
    fprintf(stderr, "%s can't be opened as a writeable-binary file.\n", outputFilePath);
    exit(EXIT_FAILURE);
  }
  printf("Decrypting %s\n", metadataEntry->pathname);
  chacha20_xor_file(fpInput, fpOutput, nonce, key, true);
  fclose(fpOutput);
  fclose(fpInput);

  int nextIndex = 0;
  if (all) {
    nextIndex = metadataEntry->index + 1;
    while(strncmp(metadataEntry->hash, dirDb[nextIndex].hash, HASH_AS_HEX_SIZE) == 0) {
      nextIndex = copyDecryptedFile(&dirDb[nextIndex], outputFilePath, outputDir);
    }
  }
  updateFileMetadata(metadataEntry, outputFilePath);
  sodium_memzero(nonce, NONCE_BYTES);
  return nextIndex;
}

/* Purpose: Copy a decrypted file to another location, byte for byte, in order
   to increase efficiency by not decrypting the file again.

   Preconditions:
   * metadataEntry is not null.
   * inputFile is opened for reading.
   * outputDir is a directory that the process has writing permissions to. */
int copyDecryptedFile(dbEntry *metadataEntry, char *inputFile, char *outputDir) {
  char outputFilePath[strlen(outputDir) + strlen(metadataEntry->pathname) + 1];
  strncpy(outputFilePath, outputDir, strlen(outputDir));
  strncat(outputFilePath, metadataEntry->pathname, strlen(metadataEntry->pathname));

  FILE *fpInput = NULL;
  FILE *fpOutput = NULL;
  
  if ( (fpInput = fopen(inputFile, "rb")) == NULL) {
    fprintf(stderr, "%s can't be opened as a readable-binary file for copying from.\n",
            inputFile);
    exit(EXIT_FAILURE);
  }
  if ( (fpOutput = fopen(outputFilePath, "wb+")) == NULL ) {
    fprintf(stderr, "%s can't be opened as a writeable-binary file.\n", outputFilePath);
    exit(EXIT_FAILURE);
  }

  unsigned char block[BLOCK_SIZE] = {0};
  size_t blockLength = 0;

  while ( (blockLength = fread(block, 1, BLOCK_SIZE, fpInput)) != 0) {
    fwrite(block, 1, blockLength, fpOutput);
    blockLength = 0;
  }
  fclose(fpInput);
  fclose(fpOutput);
  sodium_memzero(block, BLOCK_SIZE);

  updateFileMetadata(metadataEntry, outputFilePath);
  return metadataEntry->index + 1;
}

/* Purpose: Update the owner, group, permissions, access time and modification time
   of the file pointed to by outputFilePath with the metadata information coming
   from metadataEntry.

   Preconditions:
   * outputFilePath is a file and the process has write permissions for it.
   * metadataEntry is not null. */
void updateFileMetadata(dbEntry *metadataEntry, char *outputFilePath) {
  errno = 0;
  if (chown(outputFilePath, metadataEntry->uid, metadataEntry->guid) != 0) {
    if (errno == EPERM) {
      fprintf(stderr,
              "Error: The process lacks sufficient privileges "
              "to change owners of %s.\n",
              outputFilePath);
    }
    exit(EXIT_FAILURE);
  }
  if (chmod(outputFilePath, metadataEntry->mode) != 0) {
    if (errno == EPERM) {
      fprintf(stderr,
              "Error: The process lacks sufficient privileges to "
              "change permissions of %s.\n",
              outputFilePath);
    }
    exit(EXIT_FAILURE);
  }
  struct utimbuf fileTime;
  fileTime.actime = metadataEntry->accessTime;
  fileTime.modtime = metadataEntry->modTime;
  if (utime(outputFilePath, &fileTime) != 0) {
    if (errno == EACCES) {
      fprintf(stderr, "Process does not have sufficient permissions to change\
the timestamp of %s\n", outputFilePath);
    }
    exit(EXIT_FAILURE);
  }
}

/* Purpose: Collect the metadata for the directory pointed to by dirPath and store
   the result, along with dirPath in a binary tree pointed to by treeDir.

   Preconditions:
   * dirCheck has memory allocated of at least (INODE_LENGTH + DEVICE_LENGTH +
     MODE_LENGTH + GUID_LENGTH + UID_LENGTH + ACCESSTIME_LENGTH + MODTIME_LENGTH + 
     strlen(dirPath) + 8) bytes.
   * dirPath is not null.*/
void addDirToTree(char *dirPath, char *dirCheck, void ** treeDir) {
  struct stat dirAtt = {0};
  stat(dirPath, &dirAtt);
   sprintf(dirCheck, "%u\t%d\t%0o\t%d\t%d\t%d\t%d\t%s",
          (unsigned int) dirAtt.st_ino, (int) dirAtt.st_dev, dirAtt.st_mode, dirAtt.st_uid,
          dirAtt.st_gid, (int) dirAtt.st_atime, (int) dirAtt.st_mtime, dirPath);
  char *currentNode;
  currentNode = dirCheck;
  char *currentNodeCheck = NULL;
  if ( (currentNodeCheck = tsearch(currentNode, treeDir, dirTreeCmpFunc)) == NULL) {
    fprintf(stderr, "Could not add entry to binary tree. Most likely due to insufficient memory. Exiting ...\n");
    exit(EXIT_FAILURE);
  }
char *convertedNodeCheck = *(char **)currentNodeCheck;
  if (convertedNodeCheck != dirCheck) {
    cryptoFree(dirCheck, sizeof(dirCheck));
  }
}

/* Purpose: Construct the pathnames for the four database files Camera creates.

   Preconditions:
   * dbHashNoncePath has memory allocated of at least (strlen(cameraDir) +
     HASH_NONCE_DB_NAME + 1) bytes.
   * dbHashMetadataPath has memory allocated of at least (strlen(cameraDir) +
     HASH_METADATA_DB_NAME + 1) bytes.
   * dbDirPath has memory allocated of at least (strlen(cameraDir) +
     DIRECTORIES_DB_NAME + 1) bytes.
   * databaseCountPath has memory allocated of at least (strlen(cameraDir) +
     DATABASE_ENTRY_COUNT_NAME + 1) bytes. */
void constructDatabasePaths(char *cameraDir, size_t cameraDirLen, char *dbHashNoncePath,
                            char *dbHashMetadataPath, char *dbDirPath, char *databaseCountPath,
                            char *masterKeyPath, bool unencrypted) {

  strncpy(dbHashNoncePath, cameraDir, cameraDirLen);
  strncat(dbHashNoncePath, HASH_NONCE_DB_NAME, strlen(HASH_NONCE_DB_NAME));
  strncpy(dbHashMetadataPath, cameraDir, cameraDirLen);
  strncat(dbHashMetadataPath, HASH_METADATA_DB_NAME, strlen(HASH_METADATA_DB_NAME));
  strncpy(dbDirPath, cameraDir, cameraDirLen);
  strncat(dbDirPath, DIRECTORIES_DB_NAME, strlen(DIRECTORIES_DB_NAME));
  strncpy(databaseCountPath, cameraDir, cameraDirLen);
  strncat(databaseCountPath, DATABASE_ENTRY_COUNT_NAME, strlen(DATABASE_ENTRY_COUNT_NAME));
  if (!unencrypted) {
    strncpy(masterKeyPath, cameraDir, cameraDirLen);
    strncat(masterKeyPath, MASTERKEY_NAME, strlen(MASTERKEY_NAME));
  }
}

/* Purpose: Open a file pointed to by filePath with mode, mode, storing the result
   in fp and print an error message and exit if the file cannot be opened.*/
void openFile(FILE **fp, char *filePath, char *mode) {
  if ( (*fp = fopen(filePath, mode)) == NULL) {
    fprintf(stderr, "%s cannot be opened.\nExiting...\n", filePath);
    exit(EXIT_FAILURE);
  }
}

/* Purpose: Copy the contents of fpInput into fpOutput.

   Preconditions:
   * fpInput should be opened for reading.
   * fpOutput should be opened for writing. */
void createUnencryptedDb(FILE *fpInput, FILE *fpOutput) {
  size_t blockLength = 0;
  unsigned char block[BLOCK_SIZE] = {'\0'};
  
  while ( (blockLength = fread(block, 1, BLOCK_SIZE, fpInput)) != 0) {
    fwrite(block, 1, blockLength, fpOutput);
    blockLength = 0;
  }
  sodium_memzero(block, BLOCK_SIZE);
}

/* Purpose: Rewind each of the four streams to the beginning of the stream.

   Preconditions:
   * Each of the four streams must be opened in some form. */
void rewindStreams(FILE **metadataStream, FILE **nonceStream,
                   FILE **dirStream, FILE **countStream) {
  rewind(*metadataStream);
  rewind(*nonceStream);
  rewind(*dirStream);
  rewind(*countStream);
}

/* Purpose: Close each of the streams and securely free the memory of each stream.

   Preconditions:
   * Each of the four streams must be opened in some form. */
void cleanupStreams(streamStruct *metadataStream, streamStruct *nonceStream,
                    streamStruct *dirStream, streamStruct *countStream) {
  fclose(metadataStream->stream);
  fclose(nonceStream->stream);
  fclose(countStream->stream);
  fclose(dirStream->stream);
  cryptoFree(metadataStream->string, metadataStream->size);
  cryptoFree(nonceStream->string, nonceStream->size);
  cryptoFree(dirStream->string, dirStream->size);
  cryptoFree(countStream->string, countStream->size);
}

/* Purpose: Zero size bytes of data and then free data, resetting its value
   to NULL.

   Preconditions:
   * data must have had memory allocated by malloc, calloc, or realloc in some form. */
void cryptoFree(void *data, size_t size) {
  sodium_memzero(data, size);
  free(data);
  data = NULL;
}
/* Purpose: Determine if pathname is a directory or a file. If it is a directory,
   retrieve each file within pathname and its subdirectories and store the pathnames,
   one per line, in outputFile. Else, write pathname to outputFile.

   Preconditions:
   * pathname should not be null.
   * outputFile should be opened for writing. */
void collectFilesTBE(char *pathname, FILE *outputFile) {
  if (pathname[strlen(pathname) - 1] == '/') {
    fileFinder(pathname, outputFile);
  }
  else {
    char *fullFilepath = realpath(pathname, NULL);
    fprintf(outputFile, "%s\n", fullFilepath);
    cryptoFree(fullFilepath, sizeof(fullFilepath));
  }
}

/* Purpose: Derive a subkey from the master key. If the derivation
   failed, then print an error message and exit the program immediately.

   Preconditions:
   * masterKey needs to have the master key within it.
   * subkey must have storage equal to subkeyLen bytes.
   * salt cannot be null.
*/
void deriveSubkey(unsigned char *subkey[], unsigned long long subkeyLen,
                  char *masterKey, unsigned char *salt) {
  if (crypto_pwhash(*subkey, subkeyLen, masterKey, MASTER_KEY_LENGTH,
                    salt, crypto_pwhash_OPSLIMIT_SENSITIVE,
                    crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT)
      != 0) {
    fprintf(stderr, "Could not generate subkey. This is most likely due to insufficient ram.\n");
    exit(EXIT_FAILURE);
  }
}
