#pragma once

#include "source/extensions/filters/continuous_authz/recheck.h"
#include "source/extensions/filters/network/ext_authz/ext_authz.h"

namespace Envoy::Extensions::OpenZTA {

class NetworkContinuousAuthz final : public Network::ReadFilter,
                                     public Network::ConnectionCallbacks,
                                     public Authz::RequestCallbacks {
public:
  NetworkContinuousAuthz(NetworkFilters::ExtAuthz::ConfigSharedPtr config,
                         Authz::ClientPtr initial_client, Authz::ClientPtr recheck_client,
                         Random::RandomGenerator& random, RecheckSettings settings,
                         Stats::ScopeSharedPtr scope);
  ~NetworkContinuousAuthz() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  void onEvent(Network::ConnectionEvent event) override;
  void onComplete(Authz::ResponsePtr&& response) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  void startCheck();
  void revoke(absl::string_view reason);
  NetworkFilters::ExtAuthz::ConfigSharedPtr config_;
  Authz::ClientPtr initial_client_;
  Authz::ClientPtr recheck_client_;
  Random::RandomGenerator& random_;
  const RecheckSettings settings_;
  Stats::ScopeSharedPtr scope_;
  Network::ReadFilterCallbacks* callbacks_{nullptr};
  std::unique_ptr<RecheckController> controller_;
  envoy::service::auth::v3::CheckRequest snapshot_;
  bool started_{false};
  bool authorized_{false};
  bool calling_{false};
  bool in_flight_{false};
  bool closed_{false};
  bool read_setup_valid_{true};
};

} // namespace Envoy::Extensions::OpenZTA
