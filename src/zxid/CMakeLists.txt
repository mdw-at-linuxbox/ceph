#
# instead of using zxid's makefile, use this.
# zxid native build system does much we (ceph) don't need or want,
# yet doesn't do things we do need.
#
set(zxid_srcs
 src/c/zx-a-dec.c src/c/zx-ac-dec.c src/c/zx-as-dec.c src/c/zx-attrs.c
 src/c/zx-b-dec.c src/c/zx-b12-dec.c src/c/zx-cb-dec.c src/c/zx-cdm-dec.c
 src/c/zx-dap-dec.c src/c/zx-dec.c src/c/zx-demomed-dec.c
 src/c/zx-di-dec.c src/c/zx-di12-dec.c src/c/zx-dp-dec.c src/c/zx-ds-dec.c
 src/c/zx-dst-dec.c src/c/zx-e-dec.c src/c/zx-ecp-dec.c src/c/zx-elems.c
 src/c/zx-exca-dec.c src/c/zx-ff12-dec.c src/c/zx-gl-dec.c
 src/c/zx-hrxml-dec.c src/c/zx-idhrxml-dec.c src/c/zx-idp-dec.c
 src/c/zx-idpdisc-dec.c src/c/zx-im-dec.c src/c/zx-is-dec.c
 src/c/zx-is12-dec.c src/c/zx-lu-dec.c src/c/zx-m20-dec.c
 src/c/zx-md-dec.c src/c/zx-mm7-dec.c src/c/zx-ns.c src/c/zx-paos-dec.c
 src/c/zx-pmm-dec.c src/c/zx-prov-dec.c src/c/zx-ps-dec.c
 src/c/zx-sa-dec.c src/c/zx-sa11-dec.c src/c/zx-sbf-dec.c
 src/c/zx-sec-dec.c src/c/zx-sec12-dec.c src/c/zx-shibmd-dec.c
 src/c/zx-shps-dec.c src/c/zx-sp-dec.c src/c/zx-sp11-dec.c
 src/c/zx-subs-dec.c src/c/zx-tas3-dec.c src/c/zx-tas3sol-dec.c
 src/c/zx-wsc-dec.c src/c/zx-wsp-dec.c src/c/zx-wsse-dec.c
 src/c/zx-wst-dec.c src/c/zx-wsu-dec.c src/c/zx-xa-dec.c
 src/c/zx-xac-dec.c src/c/zx-xasa-dec.c src/c/zx-xasacd1-dec.c
 src/c/zx-xasp-dec.c src/c/zx-xaspcd1-dec.c src/c/zx-xenc-dec.c
 src/c/zx-xml-dec.c src/match.c src/ykaes.c src/ykcrc.c src/zxcrypto.c
 src/zxidcdc.c src/zxidcgi.c src/zxidconf.c src/zxidcurl.c src/zxiddec.c
 src/zxiddi.c src/zxidecp.c src/zxidepr.c src/zxididpx.c src/zxidim.c
 src/zxidlib.c src/zxidloc.c src/zxidmda.c src/zxidmeta.c src/zxidmk.c
 src/zxidmkwsf.c src/zxidmni.c src/zxidoauth.c src/zxidpdp.c src/zxidpep.c
 src/zxidpool.c src/zxidps.c src/zxidpsso.c src/zxidses.c src/zxidsimp.c
 src/zxidslo.c src/zxidspx.c src/zxidsso.c src/zxiduser.c src/zxidwsc.c
 src/zxidwsf.c src/zxidwsp.c src/zxlib.c src/zxlibdec.c src/zxlibenc.c
 src/zxlog.c src/zxns.c src/zxpw.c src/zxsig.c src/zxutil.c)

set(zxid_public_headers
 src/c/zxidvers.h src/c/zx-data.h src/zxidconf.h src/zxidpriv.h
 src/errmac.h src/zxidutil.h src/platform.h src/zxid.h src/zxidnoswig.h
 src/zx.h)

add_library(ceph-zxid STATIC ${zxid_srcs})
set_property(TARGET ceph-zxid
    APPEND PROPERTY COMPILE_DEFINITIONS
USE_ZXID
USE_SSL
USE_CURL
USE_OPENSSL
_REENTRANT
DEBUG
MUTEX_DEBUG=1
ENA_MCDB=1
ENA_STOMP
ENA_HTTP
LINUX)

# several things include <zx/foo> instead of foo
add_custom_target(zx-target DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/zx)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/zx
COMMAND ln -s ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/zx)
add_dependencies(ceph-zxid zx-target)
#set_property(TARGET ceph-zxid APPEND PROPERTY OBJECT_DEPENDS zx)

target_include_directories(ceph-zxid PUBLIC
${CMAKE_CURRENT_BINARY_DIR}
${CMAKE_CURRENT_SOURCE_DIR}/src/c
${CMAKE_CURRENT_SOURCE_DIR}/src)

if(THREADS_HAVE_PTHREAD_ARG)
  set_property(TARGET ceph-zxid APPEND PROPERTY COMPILE_DEFINITIONS USE_PTHREAD)
  target_compile_options(PUBLIC ceph-zxid "-pthread")
endif(THREADS_HAVE_PTHREAD_ARG)

## for now no reason to install - nobody should want to use
## this build of this library for anything outside of ceph.
#install(TARGETS ceph-zxid DESTINATION ${CMAKE_INSTALL_LIBDIR})
#install(FILES ${zxid_public_headers} DESTINATION include/zx)
