#pragma once

#include "source/extensions/filters/continuous_authz/recheck.h"
#include "source/extensions/filters/http/ext_authz/ext_authz.h"

namespace Envoy::Extensions::OpenZTA {

class HttpContinuousAuthz final : public HttpFilters::ExtAuthz::Filter {
public:
  HttpContinuousAuthz(HttpFilters::ExtAuthz::FilterConfigSharedPtr config,
                      Authz::ClientPtr initial_client, Authz::ClientPtr recheck_client,
                      Server::Configuration::ServerFactoryContext& context,
                      RecheckSettings settings, Stats::ScopeSharedPtr scope,
                      std::string resource_host);
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) override;
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) override;
  void onComplete(Authz::ResponsePtr&& response) override;
  void onDestroy() override;

private:
  void revoke(absl::string_view reason);
  HttpFilters::ExtAuthz::FilterConfigSharedPtr authorization_config_;
  Authz::ClientPtr recheck_client_;
  Server::Configuration::ServerFactoryContext& context_;
  const RecheckSettings settings_;
  Stats::ScopeSharedPtr scope_;
  const std::string resource_host_;
  Http::StreamDecoderFilterCallbacks* callbacks_{nullptr};
  std::unique_ptr<RecheckController> controller_;
  envoy::service::auth::v3::CheckRequest snapshot_;
  bool response_started_{false};
};

} // namespace Envoy::Extensions::OpenZTA
