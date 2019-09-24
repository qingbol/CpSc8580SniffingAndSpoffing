.SUFFIXES: .c .o .cpp .cc .cxx .C

UNAME = $(shell uname)
PLATFORM = $(shell uname -p)

CC = gcc
#CC = g++
#COPTS = -g -Wall
#COPTS = -g -Wno-deprecated-declarations -std=c++11
#COPTS = -g -std=c++11 -DGL_GLEXT_PROTOTYPES
COPTS = -Wall

ifeq ("$(shell uname)", "Linux")
INC =
LIBDIR = 
#LIBDIR = \
#  -L/usr/lib -L/usr/X11R6/lib
#LIBS = \
#  -lpthread -lglfw -lGLU -lGL -lGLEW -lXmu -lXi -lXext -lX11 -lm
# what learnopengl.com suggests
#LIBS = \
#  -lglfw3 -lGL -lX11 -lpthread -lXrandr -lXi -ldl
LIBS = -lpcap
else
ifeq ("$(shell uname)", "Darwin")
# INC = \
#  -I/usr/local/include
# LIBDIR = \
#   -L/usr/local/lib
# LIBS = \
#   -framework OpenGL -framework Foundation -lstdc++ -lglfw
INC =
LIBDIR = 
LIBS = -lpcap
endif
endif

.c.o:
	$(CC) -c $(INC) $(COPTS) -o $@ $<
#	gcc -c $(INC) -g -o $@ $<

.cpp.o:
	$(CC) -c $(INC) $(COPTS) -o $@ $<
#main.o: main.cpp
#shader.o: shader.h shader.cpp

#all: main
all: snoofing

OBJECTS = \
snoofing.o

main: $(OBJECTS) 
	$(CC) -o $@ $(INC) $(COPTS) $(OBJECTS) $@.o $(LIBDIR) $(LIBS)

snoofing: $(OBJECTS) 
	$(CC) -o $@ $(INC) $(COPTS) $(OBJECTS)  $(LIBDIR) $(LIBS)


clean:
	rm -f *.o
	rm -rf main
	rm -rf snoofing

