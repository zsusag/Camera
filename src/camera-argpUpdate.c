/*******************************************************************************
 * Title: camera-argpUpdate.c
 * Author(s): Zachary J. Susag - Grinnell College
 * Date Created: Friday,15 July 2016.
 * Date Revised: August  3, 2016
 * Purpose: Uses Argp from the GNU C library to parse command line options for
 *          camera-update.
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
static char docUpdate[] =
  "Adds and/or removes entries in encrypted backup";

/* Description of arguments that are accepted for camera-update. */
static char argsDocUpdate[] = "BACKUP";

/* Options for camera-update. */
static struct argp_option optionsUpdate[] = {
  {"verbose", 'v', 0, 0, "Produce verbose output" },
  {"quiet",   'q', 0, 0, "Do not produce any output to STDOUT" },
  {"silent",  's', 0, OPTION_ALIAS},
  {"database",'D', "DIR", 0,
   "Output unencrypted copies of the database files to DIR"},
  {0,0,0,0, "Input File Selection:"},
  {"mod-file",'m', "FILE", 0, "FILE should contain a list of files to be added to BACKUP, one per line"},
  {"del-file",'d', "FILE", 0, "FILE should contain a list of files to be deleted from BACKUP, one per line"},

  { 0 }
};

/* Parse a single option for camera-init. */
static error_t
parseOptUpdate (int key, char* arg, struct argp_state *state) {
  argumentsUpdate *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = true;
      break;
    case 'q': case 's':
      arguments->silent = true;
      break;
    case 'm':
      arguments->modFile = arg;
      break;
    case 'd':
      arguments->delFile = arg;
      break;
    case 'D':
      arguments->databaseDir = arg;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage (state);
      break;
    case ARGP_KEY_ARG:
      arguments->backupDir = arg;
      if (arguments->modFile == NULL && arguments->delFile == NULL) {
        argp_error(state, "You need to supply a mod-file and/or a del-file");
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* The argp parser for camera-update. */
struct argp argpUpdate = { optionsUpdate, parseOptUpdate, argsDocUpdate, docUpdate};
