TARGET_ENC     :=   suncrypt
TARGET_DEC     :=   sundec
TARGETS        :=   $(TARGET_ENC) $(TARGET_DEC)
SRC_ENC        :=   SuncryptMain.cpp Suncrypt.cpp
OBJ_ENC        :=   $(SRC_ENC:.cpp=.o)   
LINK           :=   -lgcrypt
FLAGS          :=   -std=c++0x

default: all

all: $(TARGETS)

$(TARGET_ENC): $(OBJ_ENC)
	g++ $(FLAGS) $(OBJ_ENC) -o $@ $(LINK)
     
$(TARGET_DEC):
     # gcc

%.o: %.cpp
	g++ -c $(FLAGS) $< -o $@

.PHONY: clean

clean:
	rm -f *.o $(TARGETS)