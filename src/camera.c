/*******************************************************************************
 * Title: camera.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: June 30, 2016
 * Date Revised: August  3, 2016
 * Purpose: Provide general functions for Camera
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

void keyToHash(char *keyString, unsigned char *keyHash, size_t outLen) {
  size_t keyLen = strlen(keyString);
  unsigned char keyArray[keyLen];
  for ( unsigned int i = 0; i < keyLen; i++) {
    keyArray[i] = (unsigned char) keyString[i];
  }
  crypto_generichash(keyHash, outLen, keyArray, keyLen, NULL, 0);
}

void createEncryptedFileName(char *outputDir, char *cameraDir, char *hash) {
  strncpy(cameraDir, outputDir, strlen(outputDir));
  strncat(cameraDir, "/camera/", strlen("/camera/"));
  strncat(cameraDir, hash, SPLINTER_LENGTH);
  strncat(cameraDir, "/", 1);
  strncat(cameraDir, &hash[SPLINTER_LENGTH], SPLINTER_LENGTH);
  strncat(cameraDir, "/", 1);
  strncat(cameraDir, &hash[SPLINTER_LENGTH * 2], HASH_AS_HEX_SIZE - (SPLINTER_LENGTH * 2));
}

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

int hashSort (const void * a, const void * b)
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
        fprintf(filesTBE, "%s/%s",
                //(path[strlen(path) - 1] == '/') ? "%s%s" : "%s/%s",
                fullPath, entry->d_name);
        fputc('\n', filesTBE);
        cryptoFree(fullPath);
      }
    }
  }
  closedir(dir);
}

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
      
void createOutputDirectory(char *cameraDirPath, char *outputDir, bool verbose, bool init) {
  /* 
     Append directory path with "/camera" for correct directory
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

unsigned int hashAndEncrypt(char *outputDir, FILE *filesTBE, dbEntry *database, unsigned char *key, unsigned int cursor, bool init, void **treeDir, bool verbose, bool silent, int fileCount) {
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
      sodium_memzero(fileName, sizeof(fileName));
      free(fileName);
      fileName = NULL;
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
      sodium_memzero(block, blockLength);
      blockLength = 0;
    }

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
    char outputFileName[DIRECTORY_PATH_LENGTH + outputFileDirectoryLen + 1]; 
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
        sodium_memzero(fileName, sizeof(fileName));
        free(fileName);
        fileName = NULL;
        continue;
      }
      hsearch(htableEntry, (ACTION) ENTER);
    }

    if ( (fpOutput = fopen( outputFileName, "wb+")) == NULL) {
      if (!silent) {
        fprintf(stderr, "Output file can't be opened. Continuing ...\n");
      }
      sodium_memzero(fileName, sizeof(fileName));
      free(fileName);
      fileName = NULL;
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

ssize_t getpassSafe (unsigned char *key, unsigned char *nonce) {
  char *keyAsString = NULL;
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
  nread = readline (&keyAsString, stdin);
  putchar('\n');
  /* Restore terminal. */
  (void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
  keyToHash(keyAsString, key, crypto_stream_chacha20_KEYBYTES);
  keyToHash(keyAsString, nonce, crypto_stream_chacha20_NONCEBYTES);
  sodium_memzero(keyAsString, sizeof(keyAsString));
  free(keyAsString);
  return nread;
}

int dirTreeCmpFunc (const void *a, const void *b) {
  return strcmp( strrchr((char *)a, '\t') + 1, strrchr((char *)b, '\t') + 1);
}

void nonceCopierNext(dbEntry *database, int index, char *hash, char *nonce) {
  dbEntry *currentEntry = &database[index];
  while ( strncmp(currentEntry->hash, hash, HASH_AS_HEX_SIZE) == 0 ) {
    strncpy(currentEntry->nonce, nonce, NONCE_AS_HEX_SIZE);
    currentEntry = &database[++index];
  }
}

void nonceCopierPrev(dbEntry *database, int index, char *hash, char *nonce) {
  dbEntry *currentEntry = &database[index];
  while ( strncmp(currentEntry->hash, hash, HASH_AS_HEX_SIZE) == 0) {
    strncpy(currentEntry->nonce, nonce, NONCE_AS_HEX_SIZE);
    currentEntry = &database[--index];
  }
}

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

int bsearchDirCmpFunc(const void *a, const void *b) {
  dbEntry *A = (dbEntry *)a;
  dbEntry *B = (dbEntry *)b;

  return strcmp(A->pathname, B->pathname);
}
         
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

int decryptFile(dbEntry *metadataEntry, dbEntry *dirDb, char *backupDir, char *outputDir, unsigned char *key, bool all) {
  size_t hashDirLen = strlen(backupDir);
  char hashFilePath[hashDirLen + DIRECTORY_PATH_LENGTH + 1];
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

int copyDecryptedFile(dbEntry *metadataEntry, char *inputFile, char *outputDir) {
  char outputFilePath[strlen(outputDir) + strlen(metadataEntry->pathname) + 1];
  sodium_memzero(outputFilePath, sizeof(outputFilePath));
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

void addDirToTree(char *dirPath, char *dirCheck, void ** treeDir) {
  struct stat dirAtt = {0};
  stat(dirPath, &dirAtt);
  // 7 for the \t characters & 1 for the null byte.
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
    cryptoFree(dirCheck);
  }
}

void constructDatabasePaths(char *cameraDir, size_t cameraDirLen, char *dbHashNoncePath,
                            char *dbHashMetadataPath, char *dbDirPath, char *databaseCountPath) {

  strncpy(dbHashNoncePath, cameraDir, cameraDirLen);
  strncat(dbHashNoncePath, HASH_NONCE_DB_NAME, strlen(HASH_NONCE_DB_NAME));
  strncpy(dbHashMetadataPath, cameraDir, cameraDirLen);
  strncat(dbHashMetadataPath, HASH_METADATA_DB_NAME, strlen(HASH_METADATA_DB_NAME));
  strncpy(dbDirPath, cameraDir, cameraDirLen);
  strncat(dbDirPath, DIRECTORIES_DB_NAME, strlen(DIRECTORIES_DB_NAME));
  strncpy(databaseCountPath, cameraDir, cameraDirLen);
  strncat(databaseCountPath, DATABASE_ENTRY_COUNT_NAME, strlen(DATABASE_ENTRY_COUNT_NAME));
}

void openFile(FILE **fp, char *filePath, char *mode) {
  if ( (*fp = fopen(filePath, mode)) == NULL) {
    fprintf(stderr, "%s cannot be opened.\nExiting...\n", filePath);
    exit(EXIT_FAILURE);
  }
}

void createUnencryptedDb(FILE *fpInput, FILE *fpOutput) {
  size_t blockLength = 0;
  unsigned char block[BLOCK_SIZE] = {'\0'};
  
  while ( (blockLength = fread(block, 1, BLOCK_SIZE, fpInput)) != 0) {
    fwrite(block, 1, blockLength, fpOutput);
    blockLength = 0;
  }
  sodium_memzero(block, BLOCK_SIZE);
}

void rewindStreams(FILE **metadataStream, FILE **nonceStream,
                   FILE **dirStream, FILE **countStream) {
  rewind(*metadataStream);
  rewind(*nonceStream);
  rewind(*dirStream);
  rewind(*countStream);
}

void cleanupStreams(streamStruct *metadataStream, streamStruct *nonceStream,
                    streamStruct *dirStream, streamStruct *countStream) {
  fclose(metadataStream->stream);
  fclose(nonceStream->stream);
  fclose(countStream->stream);
  fclose(dirStream->stream);
  sodium_memzero(metadataStream->string, metadataStream->size);
  sodium_memzero(nonceStream->string, nonceStream->size);
  sodium_memzero(dirStream->string, dirStream->size);
  sodium_memzero(countStream->string, countStream->size);
  free(metadataStream->string);
  free(nonceStream->string);
  free(dirStream->string);
  free(countStream->string);
}

void cryptoFree(void *data) {
  sodium_memzero(data, sizeof(data));
  free(data);
  data = NULL;
}

void collectFilesTBE(char *pathname, FILE *outputFile) {
  if (pathname[strlen(pathname) - 1] == '/') {
    fileFinder(pathname, outputFile);
  }
  else {
    char *fullFilepath = realpath(pathname, NULL);
    fprintf(outputFile, "%s\n", fullFilepath);
    cryptoFree(fullFilepath);
  }
}
