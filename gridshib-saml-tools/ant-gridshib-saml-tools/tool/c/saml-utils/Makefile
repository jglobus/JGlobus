FLAVOR=gcc32dbg

CPPFLAGS=-I$(GLOBUS_LOCATION)/include/$(FLAVOR) \
	-DPACKAGE=\"grid-proxy-utils-saml\" \
	-DVERSION=\"0.1\" \
	-DENABLE_SAML \
	-g

LDFLAGS=-L$(GLOBUS_LOCATION)/lib

GLIBS=-lssl_$(FLAVOR) \
	-lcrypto_$(FLAVOR) \
	-lglobus_gsi_sysconfig_$(FLAVOR) \
	-lglobus_gsi_proxy_core_$(FLAVOR) \
	-lglobus_gsi_credential_$(FLAVOR) \
	-lglobus_gsi_cert_utils_$(FLAVOR) \
	-lglobus_gsi_callback_$(FLAVOR) \
	-lglobus_openssl_error_$(FLAVOR) \
	-lglobus_openssl_$(FLAVOR) \
	-lglobus_common_$(FLAVOR)

LIBS=$(GLIBS)

all: grid-proxy-init grid-saml-info

grid-proxy-init: grid_proxy_init.o saml_util.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

grid-saml-info: grid_saml_info.o saml_util.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)