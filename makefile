TARGET_ENC     :=   SUNCRYPT
TARGET_DEC     :=   SUNDEC
TARGETS        :=   $(TARGET_ENC) $(TARGET_DEC)

default: all

all: $(TARGETS)

$(TARGET_ENC):
     # gcc
     
$(TARGET_DEC):
     # gcc

.PHONY: clean

clean:
     rm -f *.o $(TARGETS)