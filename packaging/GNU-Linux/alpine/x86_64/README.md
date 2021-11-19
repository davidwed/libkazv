# APKBUILD for libkazv

A file used to build libkazv in alpine (and alpine-base OS)

# Dependencies

A user in the abuild group

all package in [libkazv-deps](https://lily.kazv.moe/kazv/libkazv-deps/-/tree/alpinePackage/packaging/GNU-Linux/alpine/x86_64) that should be installed.

# Build
```
git clone https://lily.kazv.moe/kazv/libkazv-deps.git
cd libkazv/packaging/GNU-Linux/alpine/x86_64
abuild -r
```
