#include "source/extensions/filters/continuous_authz/http.h"

#include "source/common/http/header_map_impl.h"
#include "envoy/network/connection.h"
#include "envoy/ssl/connection.h"
#include "envoy/router/router.h"
#include "source/extensions/filters/common/ext_authz/check_request_utils.h"

namespace Envoy::Extensions::OpenZTA {
namespace {
const Http::LowerCaseString SessionHeader{"x-openzta-session-id"};
const Http::LowerCaseString RecheckHeader{"x-openzta-reauthorization"};
const Http::LowerCaseString XfccHeader{"x-forwarded-client-cert"};
const Http::LowerCaseString OriginalHost{"x-original-host"};
const Http::LowerCaseString OriginalMethod{"x-original-method"};
const Http::LowerCaseString OriginalPath{"x-original-path"};
} // namespace

HttpContinuousAuthz::HttpContinuousAuthz(
  HttpFilters::ExtAuthz::FilterConfigSharedPtr config, Authz::ClientPtr initial_client,
  Authz::ClientPtr recheck_client, Server::Configuration::ServerFactoryContext& context,
  RecheckSettings settings, Stats::ScopeSharedPtr scope, std::string resource_host)
    : HttpFilters::ExtAuthz::Filter(config, std::move(initial_client), context), authorization_config_(config),
      recheck_client_(std::move(recheck_client)), context_(context), settings_(settings),
      scope_(std::move(scope)), resource_host_(std::move(resource_host)) {}

void HttpContinuousAuthz::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
  HttpFilters::ExtAuthz::Filter::setDecoderFilterCallbacks(callbacks);
  controller_ = std::make_unique<RecheckController>(
    callbacks.dispatcher(), context_.api().randomGenerator(), callbacks.streamInfo(),
    std::move(recheck_client_), settings_, RecheckStats(*scope_),
    [this](absl::string_view reason) { revoke(reason); });
}

Http::FilterHeadersStatus HttpContinuousAuthz::decodeHeaders(Http::RequestHeaderMap& headers,
                                                             bool end_stream) {
  const auto connection = callbacks_->connection();
  if (!connection.has_value() || !connection->ssl() || !connection->ssl()->peerCertificateValidated()) {
    callbacks_->sendLocalReply(Http::Code::Forbidden, "OpenZTA: verified client certificate required", nullptr,
                               Grpc::Status::Unauthenticated, "openzta_unverified_client_certificate");
    return Http::FilterHeadersStatus::StopIteration;
  }
  // Bind authorization to the configured application, not a caller-controlled
  // Host routed to an unrelated, fixed upstream. Multi-resource gateways must
  // declare the binding on the selected route using trusted configuration.
  std::string resource = resource_host_;
  if (const auto route = callbacks_->route(); route) {
    const auto& metadata = route->metadata().filter_metadata();
    const auto ns = metadata.find("openzta.continuous_authz");
    if (ns != metadata.end()) {
      const auto field = ns->second.fields().find("resource_host");
      if (field != ns->second.fields().end()) {
        resource = field->second.string_value();
      }
    }
  }
  if (resource.empty() || resource.size() > 253 ||
      resource.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:[]") != std::string::npos) {
    callbacks_->sendLocalReply(Http::Code::Forbidden, "OpenZTA: invalid resource binding", nullptr,
                               Grpc::Status::PermissionDenied, "openzta_invalid_resource_binding");
    return Http::FilterHeadersStatus::StopIteration;
  }
  // Never trust a downstream phase or session id, including on HTTP/2 streams
  // which share a connection with other, independently authorized resources.
  headers.remove(RecheckHeader);
  headers.setCopy(OriginalHost, resource);
  headers.setCopy(OriginalMethod, headers.getMethodValue());
  headers.setCopy(OriginalPath, headers.getPathValue());
  const std::string session_id = fmt::format("{:016x}{:016x}",
                                             context_.api().randomGenerator().random(), context_.api().randomGenerator().random());
  headers.setCopy(SessionHeader, session_id);
  Protobuf::Map<std::string, std::string> extensions;
  extensions["openzta.session_id"] = session_id;
  extensions["openzta.resource_host"] = resource;
  Protobuf::Struct metadata;
  (*metadata.mutable_fields())["resource_host"].set_string_value(resource);
  (*metadata.mutable_fields())["session_id"].set_string_value(session_id);
  (*metadata.mutable_fields())["original_authority"].set_string_value(std::string(headers.getHostValue()));
  callbacks_->streamInfo().setDynamicMetadata("openzta.continuous_authz", metadata);
  Authz::CheckRequestUtils::createHttpCheck(
    callbacks_, headers, std::move(extensions), {}, {}, snapshot_, 0, false, false,
    true, authorization_config_->includeTLSSession(), authorization_config_->destinationLabels(),
    authorization_config_->allowedHeadersMatcher(), authorization_config_->disallowedHeadersMatcher());
  const auto& certificate = snapshot_.attributes().source().certificate();
  if (certificate.empty()) {
    callbacks_->sendLocalReply(Http::Code::Forbidden, "OpenZTA: client certificate required", nullptr,
                               Grpc::Status::Unauthenticated, "openzta_client_certificate_required");
    return Http::FilterHeadersStatus::StopIteration;
  }
  // Reconstruct the assertion from TLS even if an operator forgot HCM's
  // SANITIZE_SET option. Never relay a client-supplied certificate assertion.
  const auto xfcc = fmt::format("Cert=\"{}\"", certificate);
  headers.setCopy(XfccHeader, xfcc);
  (*snapshot_.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers())["x-forwarded-client-cert"] = xfcc;
  return HttpFilters::ExtAuthz::Filter::decodeHeaders(headers, end_stream);
}

Http::FilterHeadersStatus HttpContinuousAuthz::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                             bool end_stream) {
  response_started_ = true;
  return HttpFilters::ExtAuthz::Filter::encodeHeaders(headers, end_stream);
}

void HttpContinuousAuthz::onComplete(Authz::ResponsePtr&& response) {
  if (response && response->status == Authz::CheckStatus::OK) {
    // QUIC DATAGRAM frames have no stream flow control. The codec must drop
    // optimistic datagrams while the initial authorization request is pending,
    // rather than accumulating them behind a stopped HTTP filter chain.
    Protobuf::Struct metadata;
    (*metadata.mutable_fields())["initial_authorized"].set_bool_value(true);
    callbacks_->streamInfo().setDynamicMetadata("openzta.continuous_authz", metadata);
    controller_->start(snapshot_);
  }
  // continueDecoding() can synchronously complete and destroy this filter.
  HttpFilters::ExtAuthz::Filter::onComplete(std::move(response));
}

void HttpContinuousAuthz::onDestroy() {
  if (controller_) {
    controller_->stop();
  }
  HttpFilters::ExtAuthz::Filter::onDestroy();
}

void HttpContinuousAuthz::revoke(absl::string_view reason) {
  auto& info = callbacks_->streamInfo();
  info.setResponseFlag(StreamInfo::CoreResponseFlag::UnauthorizedExternalService);
  info.setResponseCodeDetails(reason);
  if (response_started_) {
    // RST_STREAM for HTTP/2, connection close for HTTP/1 and upgraded WebSockets.
    // A second HTTP response after SSE/gRPC response headers would corrupt the stream.
    callbacks_->resetStream(Http::StreamResetReason::LocalReset, reason);
    return;
  }
  const bool unavailable = reason == "openzta_authorization_unavailable";
  callbacks_->sendLocalReply(unavailable ? Http::Code::ServiceUnavailable : Http::Code::Forbidden,
                             unavailable ? "OpenZTA: authorization unavailable" : "OpenZTA: access revoked", nullptr,
                             unavailable ? Grpc::Status::Unavailable : Grpc::Status::PermissionDenied, reason);
}

} // namespace Envoy::Extensions::OpenZTA
