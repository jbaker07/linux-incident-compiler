savedcmd_lkm.mod := printf '%s\n'   lkm.o | awk '!x[$$0]++ { print("./"$$0) }' > lkm.mod
