echo "building linux"
cargo build --release

echo "building windows"
cargo build --release --target x86_64-pc-windows-gnu
