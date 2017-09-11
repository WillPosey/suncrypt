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
LINK_STAT_32	:=	gcrypt/libs/32/libgcrypt.a gcrypt/libs/32/libgpg-error.a 
LINK_STAT_64	:=	gcrypt/libs/64/libgcrypt.a gcrypt/libs/64/libgpg-error.a 
LINK_DYN		:=	-lgcrypt
FLAGS			:=	-std=c++0x
INC				:=	-Igcrypt/headers
TYPE 			:=	$(shell getconf LONG_BIT)

### determine if 32 bit or 64 bit system ###
### set to link against proper static library ###
ifeq ($(TYPE),64)
   LINK = $(LINK_STAT_64)
else
   LINK = $(LINK_STAT_32)
endif

### default target ###
default: all
all: $(TARGETS)

### target to compile utilizing gcrypt installation on host system ###
dynamiclink: LINK = $(LINK_DYN)
dynamiclink: INC = $()
dynamiclink: all

### rule for suncrypt ###
suncrypt: $(OBJ_ENC)
	g++ $(DEFS) $(FLAGS) $(OBJ_ENC) -o $@ $(LINK)
     
### rule for sundec ###
sundec: $(OBJ_DEC)
	g++ $(DEFS) $(FLAGS) $(OBJ_DEC) -o $@ $(LINK)

### generic rule for objects from .cpp sources ###
%.o: %.cpp
	g++ -c $(DEFS) $(FLAGS) $(INC) $< -o $@ 

### clean target ###
.PHONY: clean
clean:
	rm -f *.o $(TARGETS)