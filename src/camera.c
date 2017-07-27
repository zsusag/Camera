/*******************************************************************************
 * Title: camera.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: June 30, 2016
 * Date Revised: July 26, 2017
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
void key_to_hash(char *key_string, unsigned char *key_hash, size_t outlen) {
  
     size_t key_len = strlen(key_string);
     unsigned char key_array[key_len];
     for ( unsigned int i = 0; i < key_len; i++) {
          key_array[i] = (unsigned char) key_string[i];
     }
     crypto_generichash(key_hash, outlen, key_array, key_len, NULL, 0);
}

/* Purpose: Create the full pathname for the encrypted file described
   by hash.

   Preconditions: 
   * Storage must be allocated for cameraDir beforehand and must have
   at least (strlen(outputDir) + HASH_AS_HEX_SIZE + 11) bytes.*/
void create_encrypted_file_name(char *output_dir, char *camera_dir, char *hash) {
     strncpy(camera_dir, output_dir, strlen(output_dir));
     strncat(camera_dir, "/camera/", strlen("/camera/"));
     strncat(camera_dir, hash, SPLINTER_LENGTH);
     strncat(camera_dir, "/", 1);
     strncat(camera_dir, &hash[SPLINTER_LENGTH], SPLINTER_LENGTH);
     strncat(camera_dir, "/", 1);
     strncat(camera_dir, &hash[SPLINTER_LENGTH * 2], HASH_AS_HEX_SIZE - (SPLINTER_LENGTH * 2));
}

/* Purpose: Use the ChaCha20 stream cipher to xor fpInput and store the result
   in fpOutput.

   Preconditions:
   * fpInput must be opened for reading in binary.
   * fpOutput must be opened for writing in binary. */
void chacha20_xor_file(FILE *fp_input, FILE *fp_output,
                       unsigned char *nonce, unsigned char *key,
                       bool decrypt) {
     size_t block_length = 0;
     uint64_t block_counter = 0;
     unsigned char block[BLOCK_SIZE] = {'\0'};
     unsigned char ciphertext[BLOCK_SIZE] = {'\0'};
  
     while ( (block_length = fread(block, 1, BLOCK_SIZE, fp_input)) != 0) {
          crypto_stream_chacha20_xor_ic(ciphertext, block, block_length,
                                        nonce, block_counter, key);
          fwrite(ciphertext, 1, block_length, fp_output);
          block_counter = block_counter + (BLOCK_SIZE / 64);
          block_length = 0;
     }
     sodium_memzero(decrypt ? ciphertext : block, BLOCK_SIZE);
}
/* Purpose: Compare two hashes stored within the dbEntry structure
   alphanumerically for use in the qsort procedure.

   Preconditions:
   * Meant to be called only through one of the GNU C library sorting functions. */
int hash_compare (const void * a, const void * b) {
     db_entry_t *A = (db_entry_t *)a;
     db_entry_t *B = (db_entry_t *)b;

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
void find_files(char *path, FILE *files_tbe) {
     DIR *dir;
     struct dirent *entry;
     if ((dir = opendir(path)) != NULL) {
          while (( entry = readdir(dir)) != NULL) {
               if (entry->d_type == DT_DIR &&
                   strcmp(entry->d_name, ".") != 0 &&
                   strcmp(entry->d_name, "..") != 0) {
                    char new_path[strlen(path) + strlen(entry->d_name) + 2];
                    sodium_memzero(new_path, sizeof(new_path));
                    strncpy(new_path, path, strlen(path));
                    if ( new_path[strlen(path) - 1] != '/' )
                         new_path[strlen(path)] = '/';
                    strncat(new_path, entry->d_name, strlen(entry->d_name));
                    find_files(new_path, files_tbe);
               } else if (entry->d_type == DT_REG) {
                    char *full_path = realpath(path, NULL);
                    fprintf(files_tbe, "%s/%s", full_path, entry->d_name);
                    fputc('\n', files_tbe);
                    crypto_free(full_path, sizeof(full_path));
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
void create_output_directory(char *camera_dir_path, char *output_dir, bool verbose, bool init) {
     /* 
        Append directory path with "/camera/" for correct directory
        to be made
     */
  
     strncpy(camera_dir_path, output_dir, strlen(output_dir));
     strncat(camera_dir_path, "/camera/", strlen("/camera/"));
     /*
       Check to see if directory already exists. If it does not,
       create the directory so that only the owner can access
       the files. The directory will be made in the user's current
       working directory.
     */
     if(init) {
          struct stat st_camera_directory_test = {0};
          if (stat(camera_dir_path, &st_camera_directory_test) == -1) {
               mkdir(camera_dir_path, RWX_OWNER_PERM);
               if(verbose) {
                    printf("Creating directory \"camera\" at %s\n", camera_dir_path);
                    printf("Creating subdirectories ...\n");
               }
               char hex_chars[16] = "0123456789abcdef";
               // ab/de/ == 6 chars + '\0'
               size_t camera_dir_path_len = strlen(camera_dir_path);
               char sub_dir_path[camera_dir_path_len + 6 + 1];
               strncpy(sub_dir_path, camera_dir_path, camera_dir_path_len);
               sub_dir_path[camera_dir_path_len + SPLINTER_LENGTH] = '/';
               sub_dir_path[camera_dir_path_len + SPLINTER_LENGTH + 1] = '\0';
               for(int i = 0; i < 16; i++) {
                    for( int j = 0; j < 16; j++) {
                         sub_dir_path[camera_dir_path_len] = hex_chars[i];
                         sub_dir_path[camera_dir_path_len + 1] = hex_chars[j];
                         mkdir(sub_dir_path, RWX_OWNER_PERM);
                    }
               }
               sub_dir_path[camera_dir_path_len + 5] = '/';
               sub_dir_path[camera_dir_path_len + 6] = '\0';
               for(int i = 0; i < 16; i++) {
                    for( int j = 0; j < 16; j++) {
                         for ( int k = 0; k < 16; k++) {
                              for ( int l = 0; l < 16; l++) {
                                   sub_dir_path[camera_dir_path_len] = hex_chars[i];
                                   sub_dir_path[camera_dir_path_len + 1] = hex_chars[j];
                                   sub_dir_path[camera_dir_path_len + 3] = hex_chars[k];
                                   sub_dir_path[camera_dir_path_len + 4] = hex_chars[l];
                                   mkdir(sub_dir_path, RWX_OWNER_PERM);
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
unsigned int hash_and_encrypt(char *output_dir, FILE *files_tbe, db_entry_t *database,
                              unsigned char *encryption_key, unsigned char *hash_key,
                              unsigned int cursor, bool init, void **tree_dir,
                              bool verbose, bool silent, int file_count) {
     FILE * fp_input = NULL;
     FILE * fp_output = NULL;
  
     // Declare block buffer for reading data in from fp_input.
     unsigned char block[BLOCK_SIZE] = {0};
     size_t block_length = 0;

     /* 
        Declare variable to act as buffer from temporary file
        and opening of the file for binary read for subsequent
        encryption. The readline function will use realloc if
        the amount of space is too small for the line that is read in.
     */
     char *file_name = NULL;
     while (readline(&file_name, files_tbe) != -1) {
          // Check to see if the file can be opened as a readable-binary file.
          if ( (fp_input = fopen(file_name, "rb")) == NULL) {
               fprintf(stderr, "%s can't be opened as a readable-binary file.\n", file_name);
               crypto_free(file_name, sizeof(file_name));
               continue;
          }

          /* 
             Create a pointer to the current index of the hashNonceDb
             for increased performance instead of having to
             index the array each time. The data collection/retrieval will
             be done using purely pointer arithmetic which results in a
             slightly more optimized runtime.
          */
          db_entry_t *current_hash_entry = &database[cursor];

          /* 
             Create a buffer array to store the binary representation
             of the hash and nonce before converting them into their
             hexadecimal representations.
          */
          unsigned char bin_hash[HASH_BYTES];
          unsigned char bin_nonce[NONCE_BYTES];
    
          crypto_generichash_state state;
          crypto_generichash_init(&state, hash_key, crypto_generichash_KEYBYTES,
                                  sizeof(bin_hash));

          // Populate the nonce with random bytes.
          randombytes_buf(bin_nonce, sizeof(bin_nonce));

          /*
            Read in the file in blocks of BLOCK_SIZE bytes and update the hash with
            that block. Afterwards, set the memory of the block to zero
            and reset the block_length to 0 in preparation for new
            block to be read in.
          */
          while( (block_length = fread(block, 1, BLOCK_SIZE, fp_input)) != 0 ) {
               crypto_generichash_update(&state, block, block_length);
               // Clean up after the hash has been updated.
               block_length = 0;
          }
          sodium_memzero(block, block_length);
          crypto_generichash_final(&state, bin_hash, sizeof(bin_hash));

          sodium_bin2hex(current_hash_entry->hash, HASH_AS_HEX_SIZE + 1, bin_hash, HASH_BYTES);
    
          sodium_bin2hex(current_hash_entry->nonce, NONCE_AS_HEX_SIZE + 1,
                         bin_nonce, NONCE_BYTES);
          /*
            Write the database entry that includes the hash value for each file,
            the mode, the inode number, the device containing the file, 
            the owners user ID, and the group ID in order
            to fully reconstruct the file to its original state before the
            encryption process.
          */
          char *full_path = realpath(file_name, NULL);
          size_t dir_path_len = strlen(full_path) - strlen(strrchr(full_path, '/'));
          char dir_path[dir_path_len + 1];
          strncpy(dir_path, full_path, dir_path_len);
          dir_path[dir_path_len] = '\0';
          char *dir_check =  malloc(sizeof(char) * (INODE_LENGTH + DEVICE_LENGTH +
                                                    MODE_LENGTH + GUID_LENGTH +
                                                    UID_LENGTH + ACCESSTIME_LENGTH +
                                                    MODTIME_LENGTH + dir_path_len + 8));
          add_dir_to_tree(dir_path, dir_check, tree_dir);
          if (!silent && init && verbose) {
               printf("(%d/%d) Encrypting ... %s\n", cursor+1, file_count, full_path);
          } else if (!silent) {
               printf("Encrypting ... %s\n", full_path);
          }
        
          struct stat input_att = {0};
          stat(file_name, &input_att);

          current_hash_entry->inode = input_att.st_ino;
          current_hash_entry->device = input_att.st_dev;
          current_hash_entry->mode = input_att.st_mode;
          current_hash_entry->uid = input_att.st_uid;
          current_hash_entry->guid = input_att.st_gid;
          current_hash_entry->copy = false;
          current_hash_entry->access_time = input_att.st_atime;
          current_hash_entry->mod_time = input_att.st_mtime;
          current_hash_entry->pathname = full_path;

          int output_file_directory_len = strlen(output_dir) + strlen("/camera/");
          /* 
             Create the output_file_name from the created hash. First, copy
             the current working directory into the string, concatenate with the
             "/camera" directory, convert the hash into a string hexadecimal representation
             using the sodium_bin2hex function, and concatenate that result
             onto the final string.
          */
          char output_file_name[DIRECTORY_PATH_LENGTH + output_file_directory_len ]; 
          create_encrypted_file_name(output_dir, output_file_name, current_hash_entry->hash);
    
          if (init) {
               ENTRY htable_entry;
               htable_entry.key = current_hash_entry->hash;
               if ( hsearch(htable_entry, (ACTION) FIND) != NULL ) {
                    if (!silent) {
                         printf("Copy of %s already exists. Skipping encryption ...\n", current_hash_entry->hash);
                    }
                    current_hash_entry->copy = true;
                    cursor++;
                    sodium_memzero(output_file_name, sizeof(output_file_name));
                    fclose(fp_input);
                    crypto_free(file_name, sizeof(file_name));
                    continue;
               }
               hsearch(htable_entry, (ACTION) ENTER);
          }

          if ( (fp_output = fopen( output_file_name, "wb+")) == NULL) {
               if (!silent) {
                    fprintf(stderr, "Output file can't be opened. Continuing ...\n");
               }
               crypto_free(file_name, sizeof(file_name));
               continue;
          }

          // Go back to the beginning of the file
          rewind(fp_input);
    
          /*
            Read in blocks of BLOCK_SIZE bytes in length from the rewound input
            file. Then using the ChaCha20 stream cipher, encrypt the block
            using the generated nonce and key. Write the output to the
            output_file and set the memory of the ciphertext to 0 in preparation
            for the next block. Also set the block_length to zero for the same
            purpose and increment the block_counter by (BLOCK_SIZE / 64).
          */
          chacha20_xor_file(fp_input, fp_output, bin_nonce, encryption_key, false);
    
          /* 
             Close the input and output files before moving onto 
             the next file to be encrypted.
          */
          sodium_memzero(bin_hash, sizeof(bin_hash));
          sodium_memzero(bin_nonce, sizeof(bin_nonce));
          fclose(fp_input);
          fclose(fp_output);
          cursor++;
          sodium_memzero(file_name, sizeof(file_name));
          free(file_name);
          file_name = NULL;
     }
     sodium_memzero(file_name, sizeof(file_name));
     free(file_name);
     file_name = NULL;
     return cursor;
}

/*
  Purpose: Turn off echoing to the current terminal, prompting the user
  to enter the secret key as a string. Once entered, restore the terminal.
*/
ssize_t get_pass_safe(char **key) {
     struct termios old, new;
     int nread;
     /* Turn echoing off and fail if we can’t. */
     if (tcgetattr (fileno (stdin), &old) != 0) {
          return -1;
     }
     new = old;
     new.c_lflag &= ~ECHO;
     if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0) {
          return -1;
     }
     /* Read the password. */
     printf("Please enter the secret key: ");
     nread = readline (key, stdin);
     putchar('\n');
     /* Restore terminal. */
     (void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
     return nread;
}

/* Purpose: Compare the pathnames stored at the end of two strings, a and b,
   alphabetically. Designed to be used for the tsearch function from the GNU
   C library. */
int dir_tree_cmp_func (const void *a, const void *b) {
     return strcmp( strrchr((char *)a, '\t') + 1, strrchr((char *)b, '\t') + 1);
}

/* Purpose: If the entries after index within database are of the same hash then
   copy nonce into the appropriate field within dbEntry.

   Preconditions:
   * index is less than or equal to one minus the total number of entries database
   can store. */
void nonce_copier_next(db_entry_t *database, int index, char *hash, char *nonce) {
     db_entry_t *current_entry = &database[index];
     while ( strncmp(current_entry->hash, hash, HASH_AS_HEX_SIZE) == 0 ) {
          strncpy(current_entry->nonce, nonce, NONCE_AS_HEX_SIZE);
          current_entry = &database[++index];
     }
}

/* Purpose: If the entries before index within database are of the same hash then
   copy nonce into the appropriate field within dbEntry.

   Preconditions:
   * index is greater than 0. */
void nonce_copier_prev(db_entry_t *database, int index, char *hash, char *nonce) {
     db_entry_t *current_entry = &database[index];
     while ( strncmp(current_entry->hash, hash, HASH_AS_HEX_SIZE) == 0) {
          strncpy(current_entry->nonce, nonce, NONCE_AS_HEX_SIZE);
          current_entry = &database[--index];
     }
}

/* Purpose: Parse the information found within token and store the data
   in the appropriate fields in currentEntry.

   Preconditions:
   * token should be generated by reading in a non-empty line from either the
   hashes-metadata or directories-map database files. Regardless, the data
   needs to be separated by tab characters. */
void read_in_database(db_entry_t *current_entry, char *token, bool metadata) {
     if (metadata) {
          token = strtok(NULL,"\t");
     }
     current_entry->inode = (ino_t) strtol(token, NULL, 10);
     token = strtok(NULL, "\t");
     current_entry->device = (dev_t) strtol(token, NULL, 10);
     token = strtok(NULL, "\t");
     current_entry->mode = (mode_t) strtol(token, NULL, 8);
     token = strtok(NULL, "\t");
     current_entry->uid = (uid_t) strtol(token, NULL, 10);
     token = strtok(NULL, "\t");
     current_entry->guid = (gid_t) strtol(token, NULL, 10);
     token = strtok(NULL, "\t");
     current_entry->access_time = (time_t) strtol(token, NULL, 10);
     token = strtok(NULL, "\t");
     current_entry->mod_time = (time_t) strtol(token, NULL, 10);
     if (metadata) {
          token = strtok(NULL,"\t");
     }
     token = strtok(NULL, "\t");
     current_entry->pathname = token;
     printf("%s\t%u\t%d\t%o\t%d\t%d\t%d\t%d\t\t%s\n",
            current_entry->hash, (unsigned int) current_entry->inode,
            (int) current_entry->device,
            current_entry->mode, current_entry->uid,
            current_entry->guid, (int) current_entry->access_time,(int)
            current_entry->mod_time, current_entry->pathname);
}

/* Purpose: Mimic the "mkdir -p" command from the bash shell.

   Preconditions:
   * path should point to a directory that needs to be created.
   * dirDb should have the necessary data needed to construct
   the directory structure.
   * outputDir should point to a directory. */
int mkdir_p(char *path, char *output_dir, db_entry_t *dir_db,
            size_t dir_counter, bool verbose)
{
     size_t output_dir_len = strlen(output_dir); 
     char final_output_dir_path[output_dir_len +
                                strlen(path) + 1];
     sodium_memzero(final_output_dir_path, sizeof(final_output_dir_path));
     strncpy(final_output_dir_path, output_dir, output_dir_len);
     strncat(final_output_dir_path, path, strlen(path));
     const size_t len = strlen(final_output_dir_path);
     char new_path[PATH_MAX] = {'\0'};
     char *p;
     errno = 0;

     if (len > sizeof(new_path)-1) {
          fprintf(stderr, "Desired pathname is too long - %s.\n", path);
          exit(EXIT_FAILURE);
     }   
     strncpy(new_path, final_output_dir_path, len);

     /* Iterate the string */
     for (p = &new_path[output_dir_len] + 1; *p; p++) {
          if (*p == '/') {
               /* Temporarily truncate */
               *p = '\0';
               mkdir_p_helper(new_path, output_dir_len, dir_db, dir_counter, verbose);
               *p = '/';
          }
     }
     mkdir_p_helper(new_path, output_dir_len, dir_db, dir_counter, verbose);
     return 0;
}

/* Purpose: Compare two pathnames found within the dbEntry structure alphanumerically.
   This function was designed to be used by the bsearch function from the GNU C library,
   hence the name. */
int bsearch_dir_cmp(const void *a, const void *b) {
     db_entry_t *A = (db_entry_t *)a;
     db_entry_t *B = (db_entry_t *)b;

     return strcmp(A->pathname, B->pathname);
}

/* Purpose: Serve as a helper function to mkdir_p. Actually create the directories
   and update the permissions accordingly.

   Preconditions:
   * The same preconditions hold here as they do for mkdir_p. */
void mkdir_p_helper(char *new_path, size_t output_dir_len, db_entry_t *dir_db, size_t dir_counter, bool verbose) {
     db_entry_t check;
     check.pathname = &new_path[output_dir_len];
     db_entry_t *dir_metadata;
     if ( (dir_metadata = bsearch(&check, dir_db, dir_counter,
                                  sizeof(db_entry_t), bsearch_dir_cmp)) == NULL) {
          if (mkdir(new_path, 0700) != 0) {
               if (errno != EEXIST) {
                    fprintf(stderr, "Error occurred in creating directory, %s.\n",
                            new_path);
                    exit(EXIT_FAILURE); 
               }
          }
     }
     else {
          if (verbose) {
               printf("Creating directory: %s\n", new_path);
          }
          if (mkdir(new_path, dir_metadata->mode) != 0) {
               if (errno != EEXIST) {
                    fprintf(stderr, "Error occurred in creating directory, %s.\n",
                            new_path);
                    exit(EXIT_FAILURE); 
               }
          }
          if (chown(new_path, dir_metadata->uid, dir_metadata->guid) != 0) {
               /*if (errno == EPERM) {
                 fprintf(stderr, "Process does not have sufficient permissions to change \
                 the owner of %s\n", new_path);
                 }*/
          }
     }
}

/* Purpose: Update the access time and the modification time for all the directories
   found in path.

   Preconditions:
   * Both path and outputDir should point to directories.
   * dir_counter needs to be the number of entries within dir_db.
   * The process in which this function is called should have write permissions to the
   directory structure it is updating. */
void dir_timestamp_updater(char *path, char *output_dir, db_entry_t *dir_db, size_t dir_counter) {
     size_t output_dir_len = strlen(output_dir); 
     char final_output_dir_path[output_dir_len +
                                strlen(path) + 1];
     sodium_memzero(final_output_dir_path, sizeof(final_output_dir_path));
     strncpy(final_output_dir_path, output_dir, output_dir_len);
     strncat(final_output_dir_path, path, strlen(path));
     const size_t len = strlen(final_output_dir_path);
     char new_path[PATH_MAX] = {'\0'};
     char *p;
     errno = 0;

     strncpy(new_path, final_output_dir_path, len);

     db_entry_t *dir_metadata;
     /* Iterate the string */
     for (p = &new_path[output_dir_len] + 1; *p; p++) {
          if (*p == '/') {
               /* Temporarily truncate */
               *p = '\0';
               db_entry_t check;
               check.pathname = &new_path[output_dir_len];
               if ( (dir_metadata = bsearch(&check, dir_db, dir_counter,
                                            sizeof(db_entry_t), bsearch_dir_cmp)) != NULL) {
                    struct utimbuf dir_time;
                    dir_time.actime = dir_metadata->access_time;
                    dir_time.modtime = dir_metadata->mod_time;
                    if (utime(new_path, &dir_time) != 0) {
                         if (errno == EACCES) {
                              fprintf(stderr,
                                      "Process does not have sufficient permissions to change "
                                      "the timestamp of %s.\n",
                                      new_path);
                         }
                         exit(EXIT_FAILURE);
                    }
               }
               *p = '/';
          }
     }
     db_entry_t check;
     check.pathname = &new_path[output_dir_len];
     if ( (dir_metadata = bsearch(&check, dir_db, dir_counter,
                                  sizeof(db_entry_t), bsearch_dir_cmp)) != NULL) {
          struct utimbuf dir_time;
          dir_time.actime = dir_metadata->access_time;
          dir_time.modtime = dir_metadata->mod_time;
          if (utime(new_path, &dir_time) != 0) {
               if (errno == EACCES) {
                    fprintf(stderr,
                            "Process does not have sufficient permissions to change "
                            "the timestamp of %s.\n",
                            new_path);
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
int decrypt_file(db_entry_t *metadata_entry, db_entry_t *dir_db, char *backup_dir, char *output_dir, unsigned char *key, bool all) {
     size_t hash_dir_len = strlen(backup_dir);
     char hash_file_path[hash_dir_len + strlen("/camera/") + DIRECTORY_PATH_LENGTH];
     sodium_memzero(hash_file_path, sizeof(hash_file_path));
     create_encrypted_file_name(backup_dir, hash_file_path,
                                metadata_entry->hash);
     char output_file_path[strlen(output_dir) + strlen(metadata_entry->pathname) + 1];
     sodium_memzero(output_file_path, sizeof(output_file_path));
     strncpy(output_file_path, output_dir, strlen(output_dir));
     strncat(output_file_path, metadata_entry->pathname, strlen(metadata_entry->pathname));

     unsigned char nonce[NONCE_BYTES];
     size_t nonce_length;
     sodium_hex2bin(nonce, sizeof(nonce), metadata_entry->nonce, NONCE_AS_HEX_SIZE, NULL, &nonce_length, NULL);

     FILE *fp_input = NULL;
     FILE *fp_output = NULL;

     if ( (fp_input = fopen(hash_file_path, "rb")) == NULL) {
          fprintf(stderr, "%s can't be opened as a readable-binary file.\n", hash_file_path);
          exit(EXIT_FAILURE);
     }
  
     if ( (fp_output = fopen(output_file_path, "wb+")) == NULL ) {
          fprintf(stderr, "%s can't be opened as a writeable-binary file.\n", output_file_path);
          exit(EXIT_FAILURE);
     }
     printf("Decrypting %s\n", metadata_entry->pathname);
     chacha20_xor_file(fp_input, fp_output, nonce, key, true);
     fclose(fp_output);
     fclose(fp_input);

     int next_index = 0;
     if (all) {
          next_index = metadata_entry->index + 1;
          while(strncmp(metadata_entry->hash, dir_db[next_index].hash, HASH_AS_HEX_SIZE) == 0) {
               next_index = copy_decrypted_file(&dir_db[next_index], output_file_path, output_dir);
          }
     }
     update_file_metadata(metadata_entry, output_file_path);
     sodium_memzero(nonce, NONCE_BYTES);
     return next_index;
}

/* Purpose: Copy a decrypted file to another location, byte for byte, in order
   to increase efficiency by not decrypting the file again.

   Preconditions:
   * metadataEntry is not null.
   * inputFile is opened for reading.
   * outputDir is a directory that the process has writing permissions to. */
int copy_decrypted_file(db_entry_t *metadata_entry, char *input_file, char *output_dir) {
     char output_file_path[strlen(output_dir) + strlen(metadata_entry->pathname) + 1];
     strncpy(output_file_path, output_dir, strlen(output_dir));
     strncat(output_file_path, metadata_entry->pathname, strlen(metadata_entry->pathname));

     FILE *fp_input = NULL;
     FILE *fp_output = NULL;
  
     if ( (fp_input = fopen(input_file, "rb")) == NULL) {
          fprintf(stderr, "%s can't be opened as a readable-binary file for copying from.\n",
                  input_file);
          exit(EXIT_FAILURE);
     }
     if ( (fp_output = fopen(output_file_path, "wb+")) == NULL ) {
          fprintf(stderr, "%s can't be opened as a writeable-binary file.\n", output_file_path);
          exit(EXIT_FAILURE);
     }

     unsigned char block[BLOCK_SIZE] = {0};
     size_t block_length = 0;

     while ( (block_length = fread(block, 1, BLOCK_SIZE, fp_input)) != 0) {
          fwrite(block, 1, block_length, fp_output);
          block_length = 0;
     }
     fclose(fp_input);
     fclose(fp_output);
     sodium_memzero(block, BLOCK_SIZE);
     update_file_metadata(metadata_entry, output_file_path);
     return metadata_entry->index + 1;
}

/* Purpose: Update the owner, group, permissions, access time and modification time
   of the file pointed to by output_file_path with the metadata information coming
   from metadataEntry.

   Preconditions:
   * output_file_path is a file and the process has write permissions for it.
   * metadataEntry is not null. */
void update_file_metadata(db_entry_t *metadata_entry, char *output_file_path) {
     errno = 0;
     if (chown(output_file_path, metadata_entry->uid, metadata_entry->guid) != 0) {
          if (errno == EPERM) {
               fprintf(stderr,
                       "Error: The process lacks sufficient privileges "
                       "to change owners of %s.\n",
                       output_file_path);
          }
          exit(EXIT_FAILURE);
     }
     if (chmod(output_file_path, metadata_entry->mode) != 0) {
          if (errno == EPERM) {
               fprintf(stderr,
                       "Error: The process lacks sufficient privileges to "
                       "change permissions of %s.\n",
                       output_file_path);
          }
          exit(EXIT_FAILURE);
     }
     struct utimbuf file_time;
     file_time.actime = metadata_entry->access_time;
     file_time.modtime = metadata_entry->mod_time;
     if (utime(output_file_path, &file_time) != 0) {
          if (errno == EACCES) {
               fprintf(stderr, "Process does not have sufficient permissions to change\
the timestamp of %s\n", output_file_path);
          }
          exit(EXIT_FAILURE);
     }
}

/* Purpose: Collect the metadata for the directory pointed to by dir_path and store
   the result, along with dir_path in a binary tree pointed to by treeDir.

   Preconditions:
   * dir_check has memory allocated of at least (INODE_LENGTH + DEVICE_LENGTH +
   MODE_LENGTH + GUID_LENGTH + UID_LENGTH + ACCESSTIME_LENGTH + MODTIME_LENGTH + 
   strlen(dir_path) + 8) bytes.
   * dir_path is not null.*/
void add_dir_to_tree(char *dir_path, char *dir_check, void ** tree_dir) {
     struct stat dir_att = {0};
     stat(dir_path, &dir_att);
     sprintf(dir_check, "%u\t%d\t%0o\t%d\t%d\t%d\t%d\t%s",
             (unsigned int) dir_att.st_ino, (int) dir_att.st_dev, dir_att.st_mode, dir_att.st_uid,
             dir_att.st_gid, (int) dir_att.st_atime, (int) dir_att.st_mtime, dir_path);
     char *current_node;
     current_node = dir_check;
     char *current_node_check = NULL;
     if ( (current_node_check = tsearch(current_node, tree_dir, dir_tree_cmp_func)) == NULL) {
          fprintf(stderr, "Could not add entry to binary tree. Most likely due to insufficient memory. Exiting ...\n");
          exit(EXIT_FAILURE);
     }
     char *converted_node_check = *(char **)current_node_check;
     if (converted_node_check != dir_check) {
          crypto_free(dir_check, sizeof(dir_check));
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
void construct_database_paths(char *camera_dir, size_t camera_dir_len, char *db_hash_nonce_path,
                              char *db_hash_metadata_path, char *db_dir_path, char *database_count_path,
                              char *master_key_path, bool unencrypted) {

     strncpy(db_hash_nonce_path, camera_dir, camera_dir_len);
     strncat(db_hash_nonce_path, HASH_NONCE_DB_NAME, strlen(HASH_NONCE_DB_NAME));
     strncpy(db_hash_metadata_path, camera_dir, camera_dir_len);
     strncat(db_hash_metadata_path, HASH_METADATA_DB_NAME, strlen(HASH_METADATA_DB_NAME));
     strncpy(db_dir_path, camera_dir, camera_dir_len);
     strncat(db_dir_path, DIRECTORIES_DB_NAME, strlen(DIRECTORIES_DB_NAME));
     strncpy(database_count_path, camera_dir, camera_dir_len);
     strncat(database_count_path, DATABASE_ENTRY_COUNT_NAME, strlen(DATABASE_ENTRY_COUNT_NAME));
     if (!unencrypted) {
          strncpy(master_key_path, camera_dir, camera_dir_len);
          strncat(master_key_path, MASTERKEY_NAME, strlen(MASTERKEY_NAME));
     }
}

/* Purpose: Open a file pointed to by filePath with mode, mode, storing the result
   in fp and print an error message and exit if the file cannot be opened.*/
void open_file(FILE **fp, char *file_path, char *mode) {
     if ( (*fp = fopen(file_path, mode)) == NULL) {
          fprintf(stderr, "%s cannot be opened.\nExiting...\n", file_path);
          exit(EXIT_FAILURE);
     }
}

/* Purpose: Copy the contents of fpInput into fpOutput.

   Preconditions:
   * fpInput should be opened for reading.
   * fpOutput should be opened for writing. */
void create_unencrypted_db(FILE *fp_input, FILE *fp_output) {
     size_t block_length = 0;
     unsigned char block[BLOCK_SIZE] = {'\0'};
  
     while ( (block_length = fread(block, 1, BLOCK_SIZE, fp_input)) != 0) {
          fwrite(block, 1, block_length, fp_output);
          block_length = 0;
     }
     sodium_memzero(block, BLOCK_SIZE);
}

/* Purpose: Rewind each of the four streams to the beginning of the stream.

   Preconditions:
   * Each of the four streams must be opened in some form. */
void rewind_streams(FILE **metadata_stream, FILE **nonce_stream,
                    FILE **dir_stream, FILE **count_stream) {
     rewind(*metadata_stream);
     rewind(*nonce_stream);
     rewind(*dir_stream);
     rewind(*count_stream);
}

/* Purpose: Close each of the streams and securely free the memory of each stream.

   Preconditions:
   * Each of the five streams must be opened in some form. */
void cleanup_streams(stream_struct_t *metadata_stream, stream_struct_t *nonce_stream,
                     stream_struct_t *dir_stream, stream_struct_t *count_stream,
                     stream_struct_t *master_key_stream) {
     fclose(metadata_stream->stream);
     fclose(nonce_stream->stream);
     fclose(count_stream->stream);
     fclose(dir_stream->stream);
     fclose(master_key_stream->stream);
     crypto_free(metadata_stream->string, metadata_stream->size);
     crypto_free(nonce_stream->string, nonce_stream->size);
     crypto_free(dir_stream->string, dir_stream->size);
     crypto_free(count_stream->string, count_stream->size);
     crypto_free(master_key_stream->string, master_key_stream->size);
}

/* Purpose: Zero size bytes of data and then free data, resetting its value
   to NULL.

   Preconditions:
   * data must have had memory allocated by malloc, calloc, or realloc in some form. */
void crypto_free(void *data, size_t size) {
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
void collect_files_tbe(char *pathname, FILE *output_file) {
     if (pathname[strlen(pathname) - 1] == '/') {
          find_files(pathname, output_file);
     }
     else {
          char *full_filepath = realpath(pathname, NULL);
          fprintf(output_file, "%s\n", full_filepath);
          crypto_free(full_filepath, sizeof(full_filepath));
     }
}

/* Purpose: Derive a subkey from the master key. If the derivation
   failed, then print an error message and exit the program immediately.

   Preconditions:
   * masterKey needs to have the master key within it.
   * subkey must have storage equal to subkeyLen bytes.
   * salt cannot be null.
   */
void derive_subkey(unsigned char *subkey, unsigned long long subkey_len,
                   char *master_key, unsigned char *salt) {
     if (crypto_pwhash(subkey, subkey_len, master_key, MASTER_KEY_LENGTH,
                       salt, crypto_pwhash_OPSLIMIT_SENSITIVE,
                       crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT)
         != 0) {
          fprintf(stderr, "Could not generate subkey. This is most likely due to insufficient ram.\n");
          exit(EXIT_FAILURE);
     }
}
