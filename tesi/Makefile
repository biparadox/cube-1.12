dirs= tesi example
all:
	$(foreach N,$(dirs),make -C $(N);)
clean:
	$(foreach N,$(dirs),make clean -C $(N);)
	rm *~ *.pem *.key *.o


