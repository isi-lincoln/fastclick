## Compiling cryto things

```
git submodule update --init --recursive
cd include/cryptopp
make static
cp libcryptopp.a ../..
cd ../..
```

Now the static lib is in the correct place, we already include the headers based on the configure that generates the Makefile adding `-Iinclude`.  Now we need to edit `userlevel/Makefile` and add `-l:$(top_builddir)/libcryptopp.a` to the end of the `ccompile` line:

```
 32 ifeq ($(V),1)
 33 ccompile = $(COMPILE) $(DEPCFLAGS) $(1) -l:$(top_builddir)/libcryptopp.a
 34 ccompile_nodep = $(COMPILE) $(1)
 35 cxxcompile = $(CXXCOMPILE) $(DEPCFLAGS) $(1) -l:$(top_builddir)/libcryptopp.a
 36 cxxcompile_nodep = $(CXXCOMPILE) $(1)
 37 cxxlink = $(CXXLINK) $(1)
 38 x_verbose_cmd = $(1) $(3)
 39 verbose_cmd = $(1) $(3)
 40 else
 41 ccompile = @/bin/echo ' ' $(2) $< && $(COMPILE) $(DEPCFLAGS) $(1) -l:$(top_builddir)/libcryptopp.a
 42 ccompile_nodep = @/bin/echo ' ' $(2) $< && $(COMPILE) $(1)
 43 cxxcompile = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(DEPCFLAGS) $(1) -l:$(top_builddir)/libcryptopp.a
 44 cxxcompile_nodep = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(1)
 45 cxxlink = @/bin/echo ' ' $(2) $@ && $(CXXLINK) $(1)
 46 x_verbose_cmd = $(if $(2),/bin/echo ' ' $(2) $(3) &&,) $(1) $(3)
 47 verbose_cmd = @$(x_verbose_cmd)
 48 endif
```

