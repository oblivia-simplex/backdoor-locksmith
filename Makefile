

debug: target/debug/locksmith

release: target/release/locksmith


target/release/locksmith: Cargo.toml src/main.rs
	cargo build --release
	ls -lh target/release/locksmith


target/debug/locksmith: Cargo.toml src/main.rs
	cargo build
	ls -lh target/debug/locksmith


clean:
	rm -rf target
