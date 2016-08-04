dirs= echo_plugin file_receiver file_dealer login_verify websocket_port json_port aik_casign aik_client
all:
	$(foreach N,$(dirs),make -C $(N);)
clean:
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~
