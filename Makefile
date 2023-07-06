CC=g++
CFLAGS=-g -Wall -I .
LDFLAGS=-static -lcryptopp
SOURCES=*.cpp
OBJECTS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
EXECUTABLE=simmetry_crypt
TOOL_NAME=crypt
INSTALL_PREFIX=/usr/bin/

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(@) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $(@)

install:
	cp -f $(EXECUTABLE) $(INSTALL_PREFIX)$(TOOL_NAME)
	chmod 755 $(INSTALL_PREFIX)$(TOOL_NAME)

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	rm -f $(INSTALL_PREFIX)$(TOOL_NAME)
