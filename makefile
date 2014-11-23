#Jordan Sutton makefile
#project 3: CS457
# DNS RESOLVER
CC = g++
FLAGS = -I -Wall -g
LDFLAGS = -lm 
LINK = -lpthread
#HEADERS = awget.h 


all: myresolver 

myresolver: myresolver.o base64.o
	$(CC) $(FLAGS) -o myresolver myresolver.o base64.o

myresolver.o: myresolver.cc myresolver.h 
	$(CC) $(FLAGS) -c myresolver.cc

base64.o: base64.cc base64.h
	$(CC) $(FLAGS) -c base64.cc

clean:
	rm -rf *.o myresolver 

package:
	tar -cvf Jordan_Sutton_P3.tar makefile myresolver.h myresolver.cc README
	tar -cvf Matthew_Frahry_P3.tar makefile myresolver.h myresolver.cc README  
