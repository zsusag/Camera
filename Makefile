# Title: Makefile
# Purpose: To compile the code necessary for Camera
# Author: Zachary J. Susag | Grinnell College
###########################################################################
#  Copyright (C) 2016 Zachary John Susag
#  This file is part of Camera.
# 
#  Camera is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  Camera is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public
#  License along with Camera; if not, see
#  <http://www.gnu.org/licenses/>.
###########################################################################

CC=/usr/bin/gcc
CPPFLAGS=-I 
CFLAGS=-O -Wall -pedantic -W --std=gnu99 -g
LDFLAGS=-lm -lsodium 

all : camera-init camera-decrypt camera-update

%.o : %.c
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -c $<

camera-init : camera-init.o camera.o camera-argpInit.o
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} $^ -o $@

camera-decrypt : camera-decrypt.o camera.o camera-argpDecrypt.o
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} $^ -o $@

camera-update : camera-update.o camera.o camera-argpUpdate.o
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} $^ -o $@

clean:
	rm -f *.o
	rm -f camera-init
	rm -f camera-decrypt
	rm -f camera-update
