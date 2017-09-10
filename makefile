####################################################################################
#	Author:			William Posey
#	Course: 		University of Florida, CNT 5410
#	Semester:		Fall 2017
#	Project:		Assignment 2, Suncrypt
#	File:			makefile
#	Description:	This file is used to compile the suncrypt and sundec programs
####################################################################################
TARGETS			:=   suncrypt sundec
SRC_ENC			:=   Suncrypt.cpp SunGcrypt.cpp FileOps.cpp SuncryptSocket.cpp
OBJ_ENC			:=   $(SRC_ENC:.cpp=.o)   
SRC_DEC			:=   Sundec.cpp SunGcrypt.cpp FileOps.cpp SuncryptSocket.cpp
OBJ_DEC			:=   $(SRC_DEC:.cpp=.o)   
LINK			:=   -lgcrypt
FLAGS			:=   -std=c++0x
LINK_PATH_32	:=	L/lib/i386-linux-gnu
LINK_PATH_64	:=	L/lib/x86_64-linux-gnu



default: all
all: $(TARGETS)

### rule for suncrypt ###
suncrypt: $(OBJ_ENC)
	g++ $(FLAGS) $(OBJ_ENC) -o $@ $(LINK)
     
sundec: $(OBJ_DEC)
	g++ $(FLAGS) $(OBJ_DEC) -o $@ $(LINK)

%.o: %.cpp
	g++ -c $(FLAGS) $< -o $@ 

.PHONY: clean

clean:
	rm -f *.o $(TARGETS)