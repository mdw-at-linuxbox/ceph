// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef CEPH_RGW_KMIP_CLIENT_IMPL_H
#define CEPH_RGW_KMIP_CLIENT_IMPL_H
class RGWKMIPManagerImpl: public RGWKMIPManager {
public:
	RGWKMIPManagerImpl(CephContext *cct) : RGWKMIPManager(cct) {};
	int start();
	void stop();
};
#endif

