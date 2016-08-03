/*******************************************************************************
 * Title: camera-argpDecrypt.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: July 18, 2016
 * Date Revised: August  3, 2016
 * Purpose: Uses Argp from the GNU C library to parse command line options for
 *          camera-decrypt.
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
#include <stdbool.h>
#include <sodium.h>
#include <stdlib.h>
#include <argp.h>
#include "camera.h"

const char *argp_program_version = "Camera 1.0";
const char *argp_program_bug_address = "<susagzac@grinnell.edu>";

/* Program Documentation. */
static char docDecrypt[] =
  "Adds and/or removes entries in encrypted backup";

/* Description of arguments that are accepted for camera-update. */
static char argsDocDecrypt[] = "BACKUP [FILES...]";

/* Options for camera-update. */
static struct argp_option optionsDecrypt[] = {
  {"verbose", 'v', 0, 0, "Produce verbose output" },
  {"quiet",   'q', 0, 0, "Do not produce any output to STDOUT" },
  {"silent",  's', 0, OPTION_ALIAS},
  {"output",  'o', "DIR", 0, "Place decrypted files in DIR\nDefault: Current Working Directory"},
  {0,0,0,0, "Decrypted File Selection:"},
  {"file",    'f', "FILE", 0, "FILE should be a list of pathnames of files to be decrypted, one per line"},
  {"all",     'a', 0, 0, "Decrypts all of the files within BACKUP"},

  { 0 }
};

/* Parse a single option for camera-init. */
static error_t
parseOptDecrypt (int key, char* arg, struct argp_state *state) {
  argumentsDecrypt *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = true;
      break;
    case 'q': case 's':
      arguments->silent = true;
      break;
    case 'o':
      arguments->outputDir = arg;
      break;
    case 'f':
      arguments->inputFile = arg;
      break;
    case 'a':
      arguments->all = true;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage (state);
      break;
    case ARGP_KEY_ARG:
      arguments->backupDir = arg;
      arguments->files = &state->argv[state->next];
      state->next = state->argc;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* The argp parser for camera-update. */
struct argp argpDecrypt = { optionsDecrypt, parseOptDecrypt, argsDocDecrypt, docDecrypt};
