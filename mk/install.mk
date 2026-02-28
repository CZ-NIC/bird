# Install runtime
install: $(client) $(daemon)
	$(INSTALL) -d $(DESTDIR)/$(runstatedir)
	$(INSTALL) -d $(DESTDIR)/$(sbindir)
	$(INSTALL_PROGRAM) $(client) $(daemon) $(DESTDIR)/$(sbindir)

# Install config
install-conf:
	$(INSTALL) -d $(dir $(DESTDIR)/$(default_config_file))
	$(INSTALL_DATA) $(srcdir)/doc/bird.conf.example $(DESTDIR)/$(default_config_file)

# Install docs
install-docs: 
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(objdir)/doc/{bird,prog}{,-*}.html $(DESTDIR)/$(docdir)/

.PHONY: install install-docs 
