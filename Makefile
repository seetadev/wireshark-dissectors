PLUGIN_DIR = $(HOME)/.local/lib/wireshark/plugins
LUA_FILES = libp2p-common.lua libp2p-identify.lua libp2p-gossipsub.lua eth-consensus.lua

.PHONY: test install

test:
	@bash test.sh

install:
	mkdir -p $(PLUGIN_DIR)
	cp $(LUA_FILES) $(PLUGIN_DIR)/
