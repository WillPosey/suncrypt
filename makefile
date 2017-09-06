TARGET_ENC     :=   suncrypt
TARGET_DEC     :=   sundec
TARGETS        :=   $(TARGET_ENC) $(TARGET_DEC)
SRC_ENC        :=   Suncrypt.cpp SunGcrypt.cpp FileOps.cpp
OBJ_ENC        :=   $(SRC_ENC:.cpp=.o)   
SRC_DEC        :=   Sundec.cpp SunGcrypt.cpp FileOps.cpp
OBJ_DEC        :=   $(SRC_DEC:.cpp=.o)   
LINK           :=   -lgcrypt
FLAGS          :=   -std=c++0x

default: all

all: $(TARGETS)

$(TARGET_ENC): $(OBJ_ENC)
	g++ $(FLAGS) $(OBJ_ENC) -o $@ $(LINK)
     
$(TARGET_DEC): $(OBJ_DEC)
	g++ $(FLAGS) $(OBJ_DEC) -o $@ $(LINK)

%.o: %.cpp
	g++ -c $(FLAGS) $< -o $@

.PHONY: clean

clean:
	rm -f *.o $(TARGETS)