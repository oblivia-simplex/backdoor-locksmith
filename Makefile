


bin/locksmith: Cargo.toml src/main.rs
	sh -c "OPENSSL_DIR=openssl/local/ cargo build --release"
	mkdir -p bin
	cp target/release/locksmith bin/locksmith



openssl-1.0.2/:
	tar xzf openssl-1.0.2.tar.gz
