# BTC39GAP 1.0

## Minimum system requirements

* **64-bit operating system:** Linux, macOS, or 64-bit Windows.
* **Memory:** at least **12 GiB of physical RAM**; **16 GiB or more is recommended**.
* The production key derivation uses **8 GiB of memory** for Argon2id (`m=8 GiB, t=3, p=4`).
* **CPU:** 64-bit x86-64 or ARM64 processor. Four or more logical CPU threads are recommended.
* **Storage:** at least **50 MiB of free disk space** for the source tree, build files, and executable.
* **Build tools:** a C11-compatible GCC or Clang compiler and `make`. MinGW-w64 is required for the Windows cross-build target.
* An interactive terminal is required; all input is visible.
* **Swap/pagefile and hibernation should be disabled** before generating or recovering a wallet, to reduce the risk of secret material being written to persistent storage.
* The machine must be **fully offline and air-gapped** while generating or recovering wallets.




## Taproot output

After generating the mnemonic, the program derives exactly one Bitcoin mainnet Taproot receive address:

```text
m/86'/0'/0'/0/0
```


## Build

### Linux

```sh
make
./BTC39GAP --self-test
./BTC39GAP --qr-test
./BTC39GAP
```

### macOS

```sh
make
./BTC39GAP --self-test
./BTC39GAP --qr-test
./BTC39GAP
```

An explicit target is also available:

```sh
make mac
./BTC39GAP_mac --self-test
```

### ARM64 Linux cross-build

```sh
make arm
```

### Windows 64-bit cross-build with MinGW-w64

```sh
make win64
```

Run `BTC39GAP.exe --self-test` and then `BTC39GAP.exe --qr-test` on the Windows target before generating a wallet.

## QR test mode

Before entering any secrets, run:

```sh
./BTC39GAP --qr-test
```

This prints the official first BIP86 test-vector address and attempts to render its QR without running the 8-GiB production derivation. Scan it and verify that the scanner returns exactly the address printed by the program.
