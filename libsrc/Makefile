dirs= crypto_func struct_deal  sysfunc connector logicdb ui proclib message memdb router entity
all:
	$(foreach N,$(dirs),make -C $(N);)
clean:
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~
	rm -f lib/*.a


