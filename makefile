####################################################################################
#	Author:			William Posey
#	Course: 		University of Florida, CNT 5410
#	Semester:		Fall 2017
#	Project:		Assignment 2, Suncrypt
#	File:			makefile
#	Description:	This file is used to compile the suncrypt and sundec programs
####################################################################################
TARGETS			:=	suncrypt sundec
SRC_ENC			:=	Suncrypt.cpp SunGcrypt.cpp FileOps.cpp SuncryptSocket.cpp
OBJ_ENC			:= 	$(SRC_ENC:.cpp=.o)   
SRC_DEC			:=	Sundec.cpp SunGcrypt.cpp FileOps.cpp SuncryptSocket.cpp
OBJ_DEC			:=	$(SRC_DEC:.cpp=.o)   
FLAGS			:=	-std=c++0x

### The programs can either be compiled with the use of the installed libgcrypt.so ###
### dynamic library and /usr/include/gcrypt.h and /usr/include/gpg-error.h headers ###
### on the host system, or the static libraries for both 32 bit and 64 bit systems ###
### and the headers located in the relative directory gcrypt/headers, if libgcrypt ###
### is not installed on the host system ###
LINK_STAT_32	:=	gcrypt/libs/32/libgcrypt.a gcrypt/libs/32/libgpg-error.a 
LINK_STAT_64	:=	gcrypt/libs/64/libgcrypt.a gcrypt/libs/64/libgpg-error.a 
LINK_DYN		:=	-lgcrypt
LINK 			:=	$(LINK_DYN)
INC_HEADERS		:=	-Igcrypt/headers

### determine if 32 bit or 64 bit system ###
### set to link against proper static library ###
TYPE :=	$(shell getconf LONG_BIT)
ifeq ($(TYPE),64)
   LINK_STAT = $(LINK_STAT_64)
else
   LINK_STAT = $(LINK_STAT_32)
endif

### default target ###
default: all 
all: $(TARGETS)
	@if [ ! -e suncrypt ] && [ ! -e sundec ]; \
	then \
	echo "*********************************************************************************************************"; \
	echo "*                                                                                                       *"; \
	echo "*        Linking against dynamic libraries failed, or development headers were not installed            *"; \
	echo "*      The requried headers are gcrypt.h and gpg-error.h, which should be installed in /usr/include     *"; \
	echo "* The requried libraries are libgcrypt.so.20 and libgpg-error.so.0.10, located in /lib/<type>-linux-gnu *"; \
	echo "*                   where type is i386 for 32 bit systems and x86_64 for 64 bit systems                 *"; \
	echo "*  Compilation will be done against static libraries in gcrypt/libs with include path of gcrypt/headers *"; \
	echo "*                                                                                                       *"; \
	echo "*********************************************************************************************************"; \
	make clean; \
	make static; \
	fi

### target to compile utilizing gcrypt installation on host system, headers installed ###
static: LINK = $(LINK_STAT)
static: FLAGS += $(INC_HEADERS)
static: $(TARGETS)

### rule for suncrypt ###
suncrypt: $(OBJ_ENC)
	- g++ $(DEFS) $(FLAGS) $(OBJ_ENC) -o $@ $(LINK)
     
### rule for sundec ###
sundec: $(OBJ_DEC)
	- g++ $(DEFS) $(FLAGS) $(OBJ_DEC) -o $@ $(LINK)

### generic rule for objects from .cpp sources ###
%.o: %.cpp
	- g++ -c $(DEFS) $(FLAGS) $< -o $@ 

### clean target ###
.PHONY: clean
clean:
	rm -f *.o $(TARGETS)
	
