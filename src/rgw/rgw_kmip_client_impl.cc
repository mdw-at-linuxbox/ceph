// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "include/compat.h"
#include "common/errno.h"
#include "rgw_common.h"
#include "rgw_kmip_client.h"
#include "rgw_kmip_client_impl.h"

#include <atomic>
#include <string.h>

extern "C" {
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_memset.h"
};

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

static enum kmip_version protocol_version = KMIP_1_0;

struct RGWKmipHandle {
	int uses;
	mono_time lastuse;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	KMIP kmip_ctx[1];
	TextString textstrings[2];
	UsernamePasswordCredential upc[1];
	Credential credential[1];
	int need_to_free_kmip;
	size_t buffer_blocks, buffer_block_size, buffer_total_size;
	uint8 *encoding;

	explicit RGWKmipHandle() :
		uses(0), ctx(0), ssl(0), bio(0),
		need_to_free_kmip(0),
		encoding(0) {
			memset(kmip_ctx, 0, sizeof kmip_ctx);
			memset(textstrings, 0, sizeof textstrings);
			memset(upc, 0, sizeof upc);
			memset(credential, 0, sizeof credential);
	};
};

static void
kmip_free_handle_stuff(RGWKmipHandle *kmip)
{
	if (kmip->encoding) {
		kmip_free_buffer(kmip->kmip_ctx,
			kmip->encoding,
			kmip->buffer_total_size);
		kmip_set_buffer(kmip->kmip_ctx, NULL, 0);
	}
	if (kmip->need_to_free_kmip)
		kmip_destroy(kmip->kmip_ctx);
	if (kmip->bio)
		BIO_free_all(kmip->bio);
	if (kmip->ctx)
		SSL_CTX_free(kmip->ctx);
}

class RGWKmipHandleBuilder {
private:
	CephContext *cct;
	const char *clientcert = 0;
	const char *clientkey = 0;
	const char *capath = 0;
	const char *host = 0;
	const char *portstring = 0;
	const char *username = 0;
	const char *password = 0;
public:
	RGWKmipHandleBuilder(CephContext *cct) : cct(cct) {};
	RGWKmipHandleBuilder& set_clientcert(const std::string &v) {
		const char *s = v.c_str();
		if (*s) {
			clientcert = s;
		}
		return *this;
	}
	RGWKmipHandleBuilder& set_clientkey(const std::string &v) {
		const char *s = v.c_str();
		if (*s) {
			clientkey = s;
		}
		return *this;
	}
	RGWKmipHandleBuilder& set_capath(const std::string &v) {
		const char *s = v.c_str();
		if (*s) {
			capath = s;
		}
		return *this;
	}
	RGWKmipHandleBuilder& set_host(const char *v) {
		host = v;
		return *this;
	}
	RGWKmipHandleBuilder& set_portstring(const char *v) {
		portstring = v;
		return *this;
	}
	RGWKmipHandleBuilder& set_username(const std::string &v) {
		const char *s = v.c_str();
		if (*s) {
			username = s;
		}
		return *this;
	}
	RGWKmipHandleBuilder& set_password(const std::string& v) {
		const char *s = v.c_str();
		if (*s) {
			password = s;
		}
		return *this;
	}
	RGWKmipHandle *build() const;
};

static int
kmip_write_an_error_helper(const char *s, size_t l, void *u) {
	CephContext *cct = (CephContext *)u;
	std::string es(s, l);
	lderr(cct) << es << dendl;
	return l;
}

void
ERR_print_errors_ceph(CephContext *cct)
{
	ERR_print_errors_cb(kmip_write_an_error_helper, cct);
}

RGWKmipHandle *
RGWKmipHandleBuilder::build() const
{
	int failed = 1;
	RGWKmipHandle *r = new RGWKmipHandle();
	TextString *up = 0;
        size_t ns;

//??	OPENSSL_init_ssl(0, NULL);	// XXX
	r->ctx = SSL_CTX_new(TLS_client_method());

	if (!clientcert)
		;
	else if (SSL_CTX_use_certificate_file(r->ctx, clientcert, SSL_FILETYPE_PEM) != 1) {
		lderr(cct) << "ERROR: can't load client cert from "
			<< clientcert << dendl;
		ERR_print_errors_ceph(cct);
		goto Done;
	}

	if (!clientkey)
		;
	else if (SSL_CTX_use_PrivateKey_file(r->ctx, clientkey,
			SSL_FILETYPE_PEM) != 1) {
		lderr(cct) << "ERROR: can't load client key from "
			<< clientkey << dendl;
		ERR_print_errors_ceph(cct);
		goto Done;
	}

	if (!capath)
		;
	else if (SSL_CTX_load_verify_locations(r->ctx, capath, NULL) != 1) {
		lderr(cct) << "ERROR: can't load cacert from "
			<< capath << dendl;
		ERR_print_errors_ceph(cct);
		goto Done;
	}
	r->bio = BIO_new_ssl_connect(r->ctx);
	if (!r->bio) {
		lderr(cct) << "BIO_new_ssl_connect failed" << dendl;
		goto Done;
	}
	BIO_get_ssl(r->bio, &r->ssl);
	SSL_set_mode(r->ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(r->bio, host);
	BIO_set_conn_port(r->bio, portstring);
	if (BIO_do_connect(r->bio) != 1) {
		lderr(cct) << "BIO_do_connect failed to " << host
			<< ":" << portstring << dendl;
		ERR_print_errors_ceph(cct);
		goto Done;
	}

	// setup kmip

	kmip_init(r->kmip_ctx, NULL, 0, protocol_version);
        r->need_to_free_kmip = 1;
        r->buffer_blocks = 1;
        r->buffer_block_size = 1024;
        r->encoding = static_cast<uint8*>(r->kmip_ctx->calloc_func(
		r->kmip_ctx->state, r->buffer_blocks, r->buffer_block_size));
        if (!r->encoding) {
                lderr(cct) << "kmip buffer alloc failed: "
			<< r->buffer_blocks <<
			" * " << r->buffer_block_size << dendl;
                goto Done;
        }
        ns = r->buffer_blocks * r->buffer_block_size;
        kmip_set_buffer(r->kmip_ctx, r->encoding, ns);
        r->buffer_total_size = ns;

	up = r->textstrings;
	if (username) {
		memset(r->upc, 0, sizeof *r->upc);
		up->value = (char *) username;
		up->size = strlen(username);
		r->upc->username = up++;
		if (password) {
			up->value = (char *) password;
			up->size = strlen(password);
			r->upc->password = up++;
		}
		r->credential->credential_type = KMIP_CRED_USERNAME_AND_PASSWORD;
		r->credential->credential_value = r->upc;
		int i = kmip_add_credential(r->kmip_ctx, r->credential);
		if (i != KMIP_OK) {
			fprintf(stderr,"failed to add credential to kmip\n");
			goto Done;
		}
	}

	failed = 0;
Done:
	if (!failed)
		;
	else if (!r)
		;
	else {
		kmip_free_handle_stuff(r);
		delete r;
		r = 0;
	}
	return r;
}

struct RGWKmipHandles : public Thread {
	CephContext *cct;
	ceph::mutex cleaner_lock = ceph::make_mutex("RGWKmipHandles::cleaner_lock");
	std::vector<RGWKmipHandle*> saved_kmip;
	int cleaner_shutdown;
	ceph::condition_variable cleaner_cond;
	RGWKmipHandles(CephContext *cct) :
		cct(cct), cleaner_shutdown{0} {
	}
	RGWKmipHandle* get_kmip_handle();
	void release_kmip_handle_now(RGWKmipHandle* kmip);
	void release_kmip_handle(RGWKmipHandle* kmip);
	void flush_kmip_handles();
	void* entry();
	void stop();
};

RGWKmipHandle*
RGWKmipHandles::get_kmip_handle()
{
	RGWKmipHandle* kmip = 0;
	const char *hostaddr = cct->_conf->rgw_crypt_kmip_addr.c_str();
	{
		std::lock_guard lock{cleaner_lock};
		if (!saved_kmip.empty()) {
			kmip = *saved_kmip.begin();
			saved_kmip.erase(saved_kmip.begin());
		}
	}
	if (kmip) {
	} else if (!hostaddr) {
		// kmip = 0;
	} else {
		char *hosttemp = strdup(hostaddr);
		char *port = strchr(hosttemp, ':');
		if (port)
			*port++ = 0;
		kmip = RGWKmipHandleBuilder{cct}
			.set_clientcert(cct->_conf->rgw_crypt_kmip_client_cert)
			.set_clientkey(cct->_conf->rgw_crypt_kmip_client_key)
			.set_capath(cct->_conf->rgw_crypt_kmip_ca_path)
			.set_host(hosttemp)
			.set_portstring(port ? port : "5696")
			.set_username(cct->_conf->rgw_crypt_kmip_username)
			.set_password(cct->_conf->rgw_crypt_kmip_password)
			.build();
		free(hosttemp);
	}
	return kmip;
}

void
RGWKmipHandles::release_kmip_handle_now(RGWKmipHandle* kmip)
{
	kmip_free_handle_stuff(kmip);
	delete kmip;
}

#define MAXIDLE 5
void
RGWKmipHandles::release_kmip_handle(RGWKmipHandle* kmip)
{
	if (cleaner_shutdown) {
		release_kmip_handle_now(kmip);
	} else {
//		kmip_easy_reset(**kmip);
		std::lock_guard lock{cleaner_lock};
		kmip->lastuse = mono_clock::now();
		saved_kmip.insert(saved_kmip.begin(), 1, kmip);
	}
}

void*
RGWKmipHandles::entry()
{
	RGWKmipHandle* kmip;
	std::unique_lock lock{cleaner_lock};

	for (;;) {
		if (cleaner_shutdown) {
			if (saved_kmip.empty())
				break;
		} else {
			cleaner_cond.wait_for(lock, std::chrono::seconds(MAXIDLE));
		}
		mono_time now = mono_clock::now();
		while (!saved_kmip.empty()) {
			auto cend = saved_kmip.end();
			--cend;
			kmip = *cend;
			if (!cleaner_shutdown && now - kmip->lastuse
					< std::chrono::seconds(MAXIDLE))
				break;
			saved_kmip.erase(cend);
			release_kmip_handle_now(kmip);
		}
	}
	return nullptr;
}

void
RGWKmipHandles::stop()
{
	std::lock_guard lock{cleaner_lock};
	cleaner_shutdown = 1;
	cleaner_cond.notify_all();
}

void
RGWKmipHandles::flush_kmip_handles()
{
	stop();
	join();
	if (!saved_kmip.empty()) {
		dout(0) << "ERROR: " << __func__ << " failed final cleanup" << dendl;
	}
	saved_kmip.shrink_to_fit();
}

int
RGWKMIPManager::start()
{
	return 0;
}

void
RGWKMIPManager::stop()
{
}

int
RGWKMIPManager::add_request(RGWKMIPTransceiver *req)
{
	return 0;
}
