# *****************************************************
# Variables to control Makefile operation
 
CC = g++
CCFLAGS = -Wall -Wextra -std=c++17 -O0 -lm -g
 
# ****************************************************
# Targets needed to bring the executable up to date
 
client: client.cpp commands.cpp connection.cpp requests.cpp buffer.cpp
	$(CC) -o client client.cpp commands.cpp connection.cpp requests.cpp buffer.cpp $(CCFLAGS)

run: client
	./client

clean:
	rm -f *.o client