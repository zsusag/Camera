/*******************************************************************************
 * Title: camera-init.c
 * Author(s): Zachary John Susag - Grinnell College
 * Date Created: June 23, 2016
 * Date Revised: July 26, 2017
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
unsigned int dir_count;
stream_struct_t dir_stream;

/* This function is a helper function
   that walks the binary tree storing the
   directory metadata information and writes
   it to "fpDatabaseDir" */
void walkDirTree(const void *data, VISIT x, int level) {
     if (x == postorder || x == leaf) {
          char *str = *(char **)data;
          fprintf(dir_stream.stream, "%s\n", str);
          dir_count++;
     }
}

int main(int argc, char *argv[])
{
     arguments_init_t arguments;
     /* Default values for command line arguments */
     arguments.files = NULL;
     arguments.output_dir = NULL;
     arguments.silent = false;
     arguments.verbose = false;
     arguments.input_file = NULL;
     arguments.database_dir = NULL;
     /* Parse the command line options and arguments */
     argp_parse(&argp_init_t, argc, argv, 0, 0, &arguments);

     /* Initialize the Sodium library
        and exit immediately if it cannot
        be initialized. */
     if (sodium_init() == -1) {
          fprintf(stderr, "Sodium library could not be initialized.\n");
          return EXIT_FAILURE;
     }

     /* Prompt the user to enter, interactively,
        the secret key used for encryption and decryption
        and store the hashed version within "key". During this,
        the nonce used to encrypt the database files will be created
        from the key. */
     char *key = NULL;
     get_pass_safe(&key);
     printf("%s\n", key);
     /* Generate a new master key which will be used to generate
        the encryption and hashing subkeys. This key will later be
        written to a file and encrypted using the user provided
        key. */
     char master_key[MASTER_KEY_LENGTH];
     randombytes_buf(master_key, MASTER_KEY_LENGTH);

     /* Declare and allocate the nonces used to encrypt
        the database files. */
     unsigned char hash_nonce_nonce[crypto_stream_chacha20_NONCEBYTES];
     unsigned char hash_metadata_nonce[crypto_stream_chacha20_NONCEBYTES];
     unsigned char database_count_nonce[crypto_stream_chacha20_NONCEBYTES];
     unsigned char database_dir_nonce[crypto_stream_chacha20_NONCEBYTES];

     /* Generate the nonces randomly for the
        database files. */
     randombytes_buf(hash_nonce_nonce, crypto_stream_chacha20_NONCEBYTES);
     randombytes_buf(hash_metadata_nonce, crypto_stream_chacha20_NONCEBYTES);
     randombytes_buf(database_count_nonce, crypto_stream_chacha20_NONCEBYTES);
     randombytes_buf(database_dir_nonce, crypto_stream_chacha20_NONCEBYTES);

     /* Declare and allocate storage for the salts for the
        master key and the two subkeys: one for encryption, 
        one for hashing. */
     unsigned char master_key_salt[crypto_pwhash_SALTBYTES];
     unsigned char encryption_salt[crypto_pwhash_SALTBYTES];
     unsigned char hash_salt[crypto_pwhash_SALTBYTES];

     /* Randomly generate the salts for the master key
        and the two subkeys. */
     randombytes_buf(master_key_salt, crypto_pwhash_SALTBYTES);
     randombytes_buf(encryption_salt, crypto_pwhash_SALTBYTES);
     randombytes_buf(hash_salt, crypto_pwhash_SALTBYTES);

     /* Declare and allocate storage for the hashing key and
        the two encryption keys: one for the files being
        backed up and one for master key. */
     unsigned char master_encryption_key[crypto_stream_xchacha20_KEYBYTES];
     unsigned char encryption_key[crypto_stream_xchacha20_KEYBYTES];
     unsigned char hash_key[crypto_generichash_KEYBYTES];

     /* Derive the subkeys for encryption and hashing. */
     derive_subkey(master_encryption_key, crypto_stream_xchacha20_KEYBYTES,
                   key, master_key_salt);
     derive_subkey(encryption_key, crypto_stream_xchacha20_KEYBYTES,
                   master_key, encryption_salt);
     derive_subkey(hash_key, crypto_generichash_KEYBYTES,
                   master_key, hash_salt);

     /* Clear and free the memory storing the plaintext key. */
     crypto_free(key, sizeof(key));
     /* Remove any extra '/' or relative paths from
        the given "output_dir" and database_dir. */
     arguments.output_dir = realpath(arguments.output_dir, NULL);
  
     /* If arguments.database_dir is not equal to NULL,
        then the user wants unencrypted copies
        of the database files stored at a directory of their choosing.
        After removing any relative paths and extra '/' check to make
        sure that the directory exists. */
     if (arguments.database_dir != NULL) {
          struct stat st_dir_test = {0};
          if (stat(arguments.database_dir, &st_dir_test) == -1) {
               fprintf(stderr, "No directory under %s found.\n", arguments.database_dir);
               return EXIT_FAILURE;
          }
     }
     /* Create the output directory pathname */
     size_t camera_dir_len = strlen(arguments.output_dir) + strlen("/camera/");
     char camera_dir[camera_dir_len + 1];
     sodium_memzero(camera_dir, camera_dir_len + 1);
     create_output_directory(camera_dir, arguments.output_dir, arguments.verbose, true);
  
     /* Declare each file that will be either created or read
        from for the encryption process. */
     FILE *fp_db_hash_nonce = NULL;
     FILE *fp_db_hash_metadata = NULL;
     FILE *fp_db_count = NULL;
     FILE *fp_db_dir = NULL;

     /* Declare the file that will be used to store the master
        key alongside the nonces for the database files and
        the salts for the key derivations. */
     FILE *fp_master_key = NULL;

     /* Declare and allocate storage for the pathnames
        of each of the four database files */
     char db_hash_nonce_path[camera_dir_len + strlen(HASH_NONCE_DB_NAME) + 1];
     char db_hash_metadata_path[camera_dir_len + strlen(HASH_METADATA_DB_NAME) + 1];
     char db_dir_path[camera_dir_len + strlen(DIRECTORIES_DB_NAME) + 1];
     char database_count_path[camera_dir_len + strlen(DATABASE_ENTRY_COUNT_NAME) + 1];

     /* Declare and allocate storage for the pathname
        for the masterkey file. */
     char master_key_path[camera_dir_len + strlen(MASTERKEY_NAME) + 1];

     /* Initally clear the memory of each pathname
        to prevent garbage data being present in the pathnames */
     sodium_memzero(db_hash_nonce_path, sizeof(db_hash_nonce_path));
     sodium_memzero(db_hash_metadata_path, sizeof(db_hash_metadata_path));
     sodium_memzero(db_dir_path, sizeof(db_dir_path));
     sodium_memzero(database_count_path, sizeof(database_count_path));
     sodium_memzero(master_key_path, sizeof(master_key_path));

     /* Create the pathnames for the four database files. */
     construct_database_paths(camera_dir, camera_dir_len, db_hash_nonce_path,
                              db_hash_metadata_path, db_dir_path, database_count_path,
                              master_key_path, false);

     /* 
        Open the database files for all four of the databases for writing.
        If they cannot be opened, 
        for whatever reason, display a
        message to STDERR and exit immediately from the program.
     */
     open_file(&fp_db_hash_nonce, db_hash_nonce_path, "wb");
     open_file(&fp_db_hash_metadata, db_hash_metadata_path, "wb");
     open_file(&fp_db_dir, db_dir_path, "wb");
     open_file(&fp_db_count, database_count_path, "wb");

     /* Open the file for the master key. If it cannot be opened,
        print an error message to stderr and exit immediately
        from the program. */
     open_file(&fp_master_key, master_key_path, "wb");

     /* Declare the files that will store
        the unencrypted databases and initialize them to NULL. */
     FILE *fpu_db_hash_nonce = NULL;
     FILE *fpu_db_hash_metadata = NULL;
     FILE *fpu_db_count = NULL;
     FILE *fpu_db_dir = NULL;

     /* If the user requested unencrypted copies
        of the database files, then construct the names of these files. */
     if (arguments.database_dir != NULL) {
          size_t database_dir_len = strlen(arguments.database_dir);
          char u_hash_nonce_path[database_dir_len +
                                 strlen(HASH_NONCE_DB_NAME) + 1];
          char u_hash_metadata_path[database_dir_len +
                                    strlen(HASH_METADATA_DB_NAME) + 1];
          char u_dir_path[database_dir_len +
                          strlen(DIRECTORIES_DB_NAME) + 1];
          char u_database_count_path[database_dir_len +
                                     strlen(DATABASE_ENTRY_COUNT_NAME) + 1];
    
          sodium_memzero(u_hash_nonce_path, sizeof(u_hash_nonce_path));
          sodium_memzero(u_hash_metadata_path, sizeof(u_hash_metadata_path));
          sodium_memzero(u_dir_path, sizeof(u_dir_path));
          sodium_memzero(u_database_count_path, sizeof(u_database_count_path));

          construct_database_paths(arguments.database_dir, database_dir_len,
                                   u_hash_nonce_path, u_hash_metadata_path, u_dir_path,
                                   u_database_count_path, NULL, true);
    
          open_file(&fpu_db_hash_nonce, u_hash_nonce_path, "w");
          open_file(&fpu_db_hash_metadata, u_hash_metadata_path, "w");
          open_file(&fpu_db_dir, u_dir_path, "w");
          open_file(&fpu_db_count, u_database_count_path, "w");
     }

     /* Create a temporary file to contain
        a list of pathnames to be encrypted, one per line,
        from all of the sources available in camera-init. */
     size_t files_tbe_path_len = strlen("/tmp/cameraXXXXXX") + 1;
     char files_tbe_pathname[files_tbe_path_len];
     sodium_memzero(files_tbe_pathname, files_tbe_path_len);
     strncpy(files_tbe_pathname, "/tmp/cameraXXXXXX", files_tbe_path_len);
     int fd = mkstemp(files_tbe_pathname);
     FILE *files_tbe = fdopen(fd, "w+");
     int file_count = 0;

     /* If the user provided pathnames
        to files on the command line, then add
        these to "files_tbe". */
     if (arguments.files != NULL) {
          for (int i = 0; arguments.files[i]; i++) {
               /* If the user wants to encrypt an entire directory,
                  then call the function "find_files" to recursively
                  add the pathnames of the files within "inputDir" and
                  its subdirectories to "files_tbe" */
               collect_files_tbe(arguments.files[i], files_tbe);
          }
     }

     /* If the user provided a file which
        contains a list of pathnames of files
        they wish to have encrypted then copy these
        pathnames into "files_tbe" */
     if (arguments.input_file != NULL) {
          FILE *fp_input = NULL;
          if ( (fp_input = fopen(arguments.input_file, "r")) == NULL) {
               fprintf(stderr, "%s can't be opened as a readable file.\nExiting...\n",
                       arguments.input_file);
               return EXIT_FAILURE;
          }
          char *buffer = NULL;
          while ( readline(&buffer, fp_input) != -1) {
               collect_files_tbe(buffer, files_tbe);
          }
          crypto_free(buffer, sizeof(buffer));
          fclose(fp_input);
     }
     /* Move back to the beginning of the file for reading. */
     rewind(files_tbe);

     /* Create the hash table to check for repeated hashes. */
     if ( hcreate((size_t) file_count * 1.3) == 0 ) {
          fprintf(stderr, "Error in creating hash table. This is most likely due to insufficient memory.\nExiting ...\n");
          return EXIT_FAILURE;
     }

     /* Initalize the root of the binary tree
        which will store all of the metadata information
        about the directories containing the files
        being encrypted. */
     void *dir_tree = NULL;

     char *uniq_command = malloc((files_tbe_path_len * 2) + strlen("sort -u -o ") + 1);
     sodium_memzero(uniq_command, sizeof(uniq_command));
     sprintf(uniq_command, "sort -u -o %s %s", files_tbe_pathname, files_tbe_pathname);
     system(uniq_command);
     free(uniq_command);

     /* Count how many lines are in
        files_tbe as this might have changed
        after duplicate entries are found and
        removed. */
     char ch;
     while(!feof(files_tbe)) {
          ch = fgetc(files_tbe);
          if (ch == '\n') {
               file_count++;
          }
     }
     rewind(files_tbe);

     /* Storage location for all the metadata
        information about each file being encrypted */
     db_entry_t hash_db[file_count];

     /* Encrypt each file and write its entry
        into the "camera/" directory. First the function
        will hash the file which will be used as 
        the name of the encrypted file. Then the file will be
        encrypted  and stored within the camera directory. */
     unsigned int cursor = hash_and_encrypt(arguments.output_dir, files_tbe, hash_db, encryption_key,                                        hash_key, 0, true, &dir_tree, arguments.verbose,
                                            arguments.silent, file_count);
     /* Remove the hash table from the program. */
     hdestroy();

     /* Sort the "hash_db" in ascending, alphanumeric
        order according to the hash. */
     qsort(hash_db, (size_t) cursor, sizeof(db_entry_t), hash_compare);

     /* Declare the streamStructs for the remaining three
        database files. This structure contains all the variables
        needed to create and maintain a string stream. */
     stream_struct_t metadata_stream, nonce_stream, count_stream = {0};

     /* Declare the stream_struct_t for the master key file. */
     stream_struct_t master_key_stream = {0};

     /* Open the streams */
     metadata_stream.stream = open_memstream(&metadata_stream.string, &metadata_stream.size);
     nonce_stream.stream = open_memstream(&nonce_stream.string, &nonce_stream.size);
     dir_stream.stream = open_memstream(&dir_stream.string, &dir_stream.size);
     count_stream.stream = open_memstream(&count_stream.string, &count_stream.size);
     master_key_stream.stream = open_memstream(&master_key_stream.string, &master_key_stream.size);

     /* Format the files for initial wrtiting. */
     fprintf(metadata_stream.stream, "HASH%28s\tINODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tPATHNAME\n", " ");
     fprintf(dir_stream.stream, "INODE\t\tDEVICE\tMODE\tUID\tGUID\tACC.TIME\tMODTIME\t\tDIRNAME\n");
     fprintf(nonce_stream.stream, "HASH%28s\tNONCE\n", " ");
     fprintf(count_stream.stream, "ENTRY TYPE\tNUMBER OF ENTRIES\n");
  
     /* For every entry within "hash_db", 
        print out the contents of the array
        to the appropriate streams. After
        the data has been copied and formatted
        into the different database files, zero the 
        entries and free the allocated memory.
     */
     for ( unsigned int i = 0; i < cursor; i++) {
          db_entry_t *current_hash_entry = &hash_db[i];
          if ( current_hash_entry->copy == false ) {
               fprintf(nonce_stream.stream, "%s\t%s\n",
                       current_hash_entry->hash,
                       current_hash_entry->nonce);
          }
          fprintf(metadata_stream.stream, "%s\t%u\t%d\t%0o\t%d\t%d\t%d\t%d\t%s\n",
                  current_hash_entry->hash, (unsigned int) current_hash_entry->inode,
                  (int) current_hash_entry->device,
                  current_hash_entry->mode, current_hash_entry->uid,
                  current_hash_entry->guid, (int) current_hash_entry->access_time,(int)
                  current_hash_entry->mod_time, current_hash_entry->pathname);
          /* Free the memory as the DB files are being written of each pathname. */
          crypto_free(current_hash_entry->pathname, sizeof(current_hash_entry->pathname));
     }
     dir_count = 0;
     /* Walk through the binary
        tree containing the metadata on the
        directories in-order. During this walk-through
        the data will be formatted and printed
        to the dir_stream. */
     twalk(dir_tree, walkDirTree);

     /* Print the count of how many entries are
        within the "hashes-metadata" and
        "directories-map" database files. */
     fprintf(count_stream.stream, "%s\t%d\n", "Hash metadata", cursor);
     fprintf(count_stream.stream, "%s\t%d\n", "Directory count", dir_count);

     /* Rewind the streams before having the data
        read from them */
     rewind_streams(&metadata_stream.stream, &nonce_stream.stream,
                    &dir_stream.stream, &count_stream.stream);

     /* Write the encrypted database files
        out to the appropriate locations */
     if (arguments.verbose) {
          printf("Writing database files to %s/camera\n", arguments.output_dir);
     }

     chacha20_xor_file(metadata_stream.stream, fp_db_hash_metadata, hash_metadata_nonce,
                       encryption_key, false);
     chacha20_xor_file(nonce_stream.stream, fp_db_hash_nonce, hash_nonce_nonce,
                       encryption_key, false);
     chacha20_xor_file(count_stream.stream, fp_db_count, database_count_nonce,
                       encryption_key, false);
     chacha20_xor_file(dir_stream.stream, fp_db_dir, database_dir_nonce,
                       encryption_key, false);

     /* If the user requested that unencrypted copies of
        the database files were to be made, then rewind the streams again,
        copy the contents of the stream into the unencrypted database
        files and close the unencrypted database files */
     if (arguments.database_dir != NULL) {
          if (arguments.verbose) {
               printf("Writing unencrypted database files to %s\n", arguments.database_dir);
          }
          rewind_streams(&metadata_stream.stream, &nonce_stream.stream,
                         &dir_stream.stream, &count_stream.stream);
          create_unencrypted_db(metadata_stream.stream, fpu_db_hash_metadata);
          create_unencrypted_db(nonce_stream.stream, fpu_db_hash_nonce);
          create_unencrypted_db(count_stream.stream, fpu_db_count);
          create_unencrypted_db(dir_stream.stream, fpu_db_dir);
          fclose(fpu_db_hash_metadata);
          fclose(fpu_db_hash_nonce);
          fclose(fpu_db_count);
          fclose(fpu_db_dir);
     }

     /* Generate the nonce needed to encrypt the master key file. */
     unsigned char master_key_nonce[crypto_stream_xchacha20_NONCEBYTES];
     randombytes_buf(master_key_nonce, crypto_stream_xchacha20_NONCEBYTES);

     /* Print to the file the nonce and salt needed to decrypt
        the master key file.*/
     fwrite(master_key_salt, 1, crypto_pwhash_SALTBYTES,
            fp_master_key);
     fwrite(master_key_nonce, 1, crypto_stream_xchacha20_NONCEBYTES,
            fp_master_key);

     /* Populate the master_key_stream with all the needed information
        that will be encrypted: master key, nonces for the database
        files, and salts for the subkeys. */
     fprintf(master_key_stream.stream, master_key);
     fwrite(encryption_salt, 1, crypto_pwhash_SALTBYTES,
            master_key_stream.stream);
     fwrite(hash_salt, 1, crypto_pwhash_SALTBYTES,
            master_key_stream.stream);
     fwrite(hash_nonce_nonce, 1, crypto_stream_chacha20_NONCEBYTES,
            master_key_stream.stream);
     fwrite(hash_metadata_nonce, 1, crypto_stream_chacha20_NONCEBYTES,
            master_key_stream.stream);
     fwrite(database_count_nonce, 1, crypto_stream_chacha20_NONCEBYTES,
            master_key_stream.stream);
     fwrite(database_dir_nonce, 1, crypto_stream_chacha20_NONCEBYTES,
            master_key_stream.stream);
  
     /* Write out and encrypt the master key file which contains
        the master key and all the nonces for the database
        files. */
     chacha20_xor_file(master_key_stream.stream, fp_master_key, master_key_nonce,
                       master_encryption_key, false);

     /* Zero out the memory of sensitive data before
        exiting the program. */
     sodium_memzero(master_key_nonce, sizeof(master_key_nonce));
     sodium_memzero(master_key, sizeof(master_key));
     sodium_memzero(hash_nonce_nonce, sizeof(hash_nonce_nonce));
     sodium_memzero(hash_metadata_nonce, sizeof(hash_metadata_nonce));
     sodium_memzero(database_count_nonce, sizeof(database_count_nonce));
     sodium_memzero(database_dir_nonce, sizeof(database_dir_nonce));
     sodium_memzero(master_key_salt, sizeof(master_key_salt));
     sodium_memzero(encryption_salt, sizeof(encryption_salt));
     sodium_memzero(hash_salt, sizeof(hash_salt));
     sodium_memzero(master_encryption_key, sizeof(master_encryption_key));
     sodium_memzero(encryption_key, sizeof(encryption_key));
     sodium_memzero(hash_key, sizeof(hash_key));
  
     /* TODO: Need to cryptofree stuff as well as close all of the streams and files. */
     tdestroy(dir_tree, free);
     /* Close the streams as they are no longer needed. */
     cleanup_streams(&metadata_stream, &nonce_stream, &dir_stream, &count_stream,
                     &master_key_stream);
     /* Free any remaining allocated data 
        and close any remaining open files. */
     free(arguments.output_dir);
     remove(files_tbe_pathname);
     fclose(files_tbe);
     fclose(fp_db_hash_nonce);
     fclose(fp_db_hash_metadata);
     fclose(fp_db_dir);
     fclose(fp_db_count);
     fclose(fp_master_key);
     return EXIT_SUCCESS;
}
