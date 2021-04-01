OBJECTS = get_original_addr.o
OUTFILE = liboriginaddr.so
COMPILE_OPT = -fPIC -shared
test: $(OBJECTS)
	gcc -o $(OUTFILE) $(COMPILE_OPT) $(OBJECTS)
get_original_addr.o: get_original_addr.c
	gcc -c get_original_addr.c
clean: 
	rm $(OBJECTS)
	rm $(OUTFILE)
