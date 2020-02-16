// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef CEPH_RGW_KMIP_CLIENT_H
#define CEPH_RGW_KMIP_CLIENT_H

class RGWKMIPManager;

class RGWKMIPTransceiver {
public:
	enum kmip_operation {
		CREATE,
		LOCATE,
		GET,
		GET_ATTRIBUTES,
		GET_ATTRIBUTE_LIST,
		DESTROY
	};
	CephContext *cct;
	kmip_operation operation;
	string key_name;
	char *name = 0;
	char *unique_id = 0;
	char *out;
	int ret;
	bool done;
	ceph::mutex lock = ceph::make_mutex("rgw_kmip_req::lock");
	ceph::condition_variable cond;

	int wait(optional_yield y);
	RGWKMIPTransceiver(CephContext * const cct,
		kmip_operation operation,
		const boost::string_view & key_name
	)
	: cct(cct),
		operation(operation),
		key_name(key_name),
		ret(-1),
		done(false)
	{}

	int send();
	int process(optional_yield y);
};

class RGWKMIPManager {
protected:
	CephContext *cct;
	bool is_started = false;
	RGWKMIPManager(CephContext *cct) : cct(cct) {};
public:
	virtual ~RGWKMIPManager() = 0;
	virtual int start();
	virtual void stop();
	virtual int add_request(RGWKMIPTransceiver*);
};

void rgw_kmip_client_init(RGWKMIPManager &);
void rgw_kmip_client_cleanup();
#endif
