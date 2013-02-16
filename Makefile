
CXXFLAGS = -O0 -g -Wextra -Wall

msshlnk: main.o

objects = main.o

msshlnk : $(objects)
	c++ -g -o msshllnk $(objects)

clean:
	rm -f $(objects)
