all: main2

main2: main2.o
	g++ -o main2 main2.o

main2.o: main2.cpp
	g++ -c main2.cpp -std=gnu++0x
