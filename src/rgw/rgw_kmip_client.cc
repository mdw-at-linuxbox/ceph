// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "common/Thread.h"
#include "include/compat.h"
#include "common/errno.h"
#include "rgw_common.h"
#include "rgw_kmip_client.h"

#include <atomic>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

RGWKMIPManager *rgw_kmip_manager;

int
RGWKMIPTransceiver::wait(optional_yield y)
{
	if (done)
		return ret;
	std::unique_lock l{lock};
	if (!done)
		cond.wait(l);
	return ret;
}

int
RGWKMIPTransceiver::send()
{
	int r = rgw_kmip_manager->add_request(this);
	return r;
}

int
RGWKMIPTransceiver::process(optional_yield y)
{
	int r = send();
	if (r < 0)
		return r;
	return wait(y);
}

void
rgw_kmip_client_init(RGWKMIPManager *m)
{
	rgw_kmip_manager = m;
	rgw_kmip_manager->start();
}

void
rgw_kmip_client_cleanup()
{
	rgw_kmip_manager->stop();
	delete rgw_kmip_manager;
}
