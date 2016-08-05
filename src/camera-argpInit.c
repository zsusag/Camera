/*******************************************************************************
 * Title: camera-argpInit.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: July 11, 2016
 * Date Revised: August  5, 2016
 * Purpose: Uses Argp from the GNU C library to parse command line options for
 *          camera-init.
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

#include <stdlib.h>
#include <stdbool.h>
#include <argp.h>
#include <sodium.h>
#include "camera.h"

const char *argp_program_version = "Camera 1.0";
const char *argp_program_bug_address = "<susagzac@grinnell.edu>";

/* Program Documentation. */
static char docInit[] =
  "Initialize an encrypted backup directory using the ChaCha20 stream cipher";

/* Description of arguments that are accepted for camera-init. */
static char argsDocInit[] = "OUTPUT_DIR [FILES/DIRs...]";

/* Options for camera-init. */
static struct argp_option optionsInit[] = {
  {"database",'D', "DIR", 0,
   "Output unencrypted copies of the database files to DIR", 1},
  {0,0,0,0, "Options related to initial files to be encrypted:"},
  {"file",     'f', "FILE", 0, "FILE should contain a list of files to be encrypted, one per line"},
  {"verbose", 'v', 0, 0, "Produce verbose output", -1 },
  {"quiet",   'q', 0, 0, "Do not produce any output", -1},
  {"silent",  's', 0, OPTION_ALIAS, "", -1},
  
  { 0 }
};

/* Parse a single option for camera-init. */
static error_t
parseOptInit (int key, char* arg, struct argp_state *state) {
  argumentsInit *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = true;
      break;
    case 'q': case 's':
      arguments->silent = true;
      break;
    case 'D':
      arguments->databaseDir = arg;
      break;
    case 'f':
      arguments->inputFile = arg;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      arguments->outputDir = arg;
      arguments->files = &state->argv[state->next];
      state->next = state->argc;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* The argp parser for camera-init. */
struct argp argpInit = { optionsInit, parseOptInit, argsDocInit, docInit };
      
