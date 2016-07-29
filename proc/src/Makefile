dirs= echo_plugin file_receiver login_verify websocket_port json_port 
all:
	$(foreach N,$(dirs),make -C $(N);)
clean:
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~
