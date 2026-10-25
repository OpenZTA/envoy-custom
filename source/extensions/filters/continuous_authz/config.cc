#include "api/extensions/filters/continuous_authz/continuous_authz.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/grpc/async_client_manager.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/common/ext_authz/ext_authz_grpc_impl.h"
#include "source/extensions/filters/common/ext_authz/ext_authz_http_impl.h"
#include "source/extensions/filters/continuous_authz/http.h"
#include "source/extensions/filters/continuous_authz/network.h"
#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy::Extensions::OpenZTA {
namespace {

using MakeClient = std::function<Authz::ClientPtr()>;

// NAC is an authorization endpoint, not an application route. Always use a
// header-only POST to its exact endpoint, including for WebDAV/custom methods.
// Preserve the original operation in the trusted x-original-* assertions.
class BoundAuthorizationClient final : public Authz::Client {
public:
  BoundAuthorizationClient(Authz::ClientPtr client, std::string path)
      : client_(std::move(client)), path_(std::move(path)) {}
  void cancel() override { client_->cancel(); }
  const StreamInfo::StreamInfo* streamInfo() const override { return client_->streamInfo(); }
  void check(Authz::RequestCallbacks& callbacks,
             const envoy::service::auth::v3::CheckRequest& request,
             Tracing::Span& span, const StreamInfo::StreamInfo& info) override {
    auto normalized = request;
    std::string resource;
    const auto& extensions = request.attributes().context_extensions();
    const auto phase = extensions.find("openzta.phase");
    const auto binding = extensions.find("openzta.resource_host");
    if (phase != extensions.end() && phase->second == "recheck" && binding != extensions.end()) {
      // Periodic checks keep the immutable original route binding, even if a
      // later filter has rewritten the application's headers or metadata.
      resource = binding->second;
    } else {
      const auto& metadata = info.dynamicMetadata().filter_metadata();
      const auto ns = metadata.find("openzta.continuous_authz");
      if (ns != metadata.end()) {
        const auto field = ns->second.fields().find("resource_host");
        if (field != ns->second.fields().end()) {
          resource = field->second.string_value();
        }
      }
    }
    if (resource.empty()) {
      auto error = std::make_unique<Authz::Response>();
      error->status = Authz::CheckStatus::Error;
      callbacks.onComplete(std::move(error));
      return;
    }
    (*normalized.mutable_attributes()->mutable_context_extensions())["openzta.resource_host"] = resource;
    (*normalized.mutable_attributes()->mutable_destination()->mutable_labels())["resource_host"] = resource;
    auto* http = normalized.mutable_attributes()->mutable_request()->mutable_http();
    // UHV represents extended CONNECT internally as GET + Upgrade. Policies
    // must receive the actual WebTransport operation, including over gRPC.
    const auto original_method = http->headers().find("x-original-method");
    if (original_method != http->headers().end() && !original_method->second.empty()) {
      const std::string method = original_method->second;
      http->set_method(method);
      (*http->mutable_headers())[":method"] = method;
    }
    http->set_host(resource);
    (*http->mutable_headers())[":authority"] = resource;
    (*http->mutable_headers())["x-original-host"] = resource;
    if (!path_.empty()) {
      http->set_method("POST");
      http->set_path(path_);
      (*http->mutable_headers())[":method"] = "POST";
      (*http->mutable_headers())[":path"] = path_;
    }
    client_->check(callbacks, normalized, span, info);
  }

private:
  Authz::ClientPtr client_;
  const std::string path_;
};

MakeClient grpcClientFactory(const envoy::config::core::v3::GrpcService& grpc_service,
                             Server::Configuration::ServerFactoryContext& context) {
  const uint32_t timeout = PROTOBUF_GET_MS_OR_DEFAULT(grpc_service, timeout, 2000);
  Envoy::Grpc::GrpcServiceConfigWithHashKey key(grpc_service);
  return [&context, key, timeout]() -> Authz::ClientPtr {
    auto client = context.clusterManager().grpcAsyncClientManager().getOrCreateRawAsyncClientWithHashKey(key, context.scope(), true);
    THROW_IF_NOT_OK_REF(client.status());
    return std::make_unique<Authz::GrpcClientImpl>(client.value(), std::chrono::milliseconds(timeout));
  };
}

class HttpFactory final : public HttpFilters::Common::FactoryBase<Api::HttpContinuousAuthz> {
public:
  HttpFactory()
      : FactoryBase("openzta.filters.http.continuous_authz") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
    const Api::HttpContinuousAuthz& proto, const std::string& prefix,
    Server::Configuration::FactoryContext& context) override {
    return createFilterFactoryFromProtoWithServerContextTyped(proto, prefix, context.serverFactoryContext());
  }

  Http::FilterFactoryCb createFilterFactoryFromProtoWithServerContextTyped(
    const Api::HttpContinuousAuthz& proto, const std::string& prefix,
    Server::Configuration::ServerFactoryContext& context) override {
    auto authorization = proto.authorization();
    if (authorization.failure_mode_allow() || authorization.has_with_request_body() ||
        authorization.has_filter_enabled() || authorization.has_filter_enabled_metadata() ||
        authorization.encode_raw_headers() || authorization.clear_route_cache()) {
      throw EnvoyException("continuous_authz requires fail-closed, header-only authorization without bypasses");
    }
    authorization.set_include_peer_certificate(true);
    if (proto.resource_host().empty() || proto.resource_host().size() > 253 ||
        proto.resource_host().find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:[]") != std::string::npos) {
      throw EnvoyException("continuous_authz requires a valid immutable resource_host binding");
    }
    if (authorization.has_http_service()) {
      for (const auto& header : authorization.http_service().authorization_request().headers_to_add()) {
        const auto name = Http::LowerCaseString(header.key()).get();
        if (name == "x-forwarded-client-cert" || name == "x-openzta-session-id" ||
            name == "x-openzta-reauthorization" || name == "x-original-host" ||
            name == "x-original-method" || name == "x-original-path" ||
            name == ":authority" || name == "host" || name == ":method" || name == ":path") {
          throw EnvoyException("continuous_authz reserved authorization assertions cannot be overridden");
        }
      }
      // Reserved metadata must reach NAC API for both initial and periodic checks.
      auto* allow = authorization.mutable_allowed_headers();
      for (const auto* name : {"x-forwarded-client-cert", "x-openzta-session-id", "x-openzta-reauthorization",
                               "x-original-host", "x-original-method", "x-original-path"}) {
        allow->add_patterns()->set_exact(name);
      }
    }
    const auto config = std::make_shared<HttpFilters::ExtAuthz::FilterConfig>(
      authorization, context.scope(), prefix, context);
    MakeClient make_client;
    if (authorization.has_http_service()) {
      const auto& service = authorization.http_service();
      const uint32_t timeout = PROTOBUF_GET_MS_OR_DEFAULT(service.server_uri(), timeout, 2000);
      const std::string path = service.path_prefix().empty() ? "/api/v1/verify" : service.path_prefix();
      if (path.front() != '/') {
        throw EnvoyException("continuous_authz: authorization path must start with /");
      }
      const auto client_config = std::make_shared<Authz::ClientConfig>(
        authorization, timeout, "", context);
      make_client = [&context, client_config, path]() -> Authz::ClientPtr {
        return std::make_unique<BoundAuthorizationClient>(
          std::make_unique<Authz::RawHttpClientImpl>(context.clusterManager(), client_config), path);
      };
    } else {
      THROW_IF_NOT_OK(Config::Utility::checkTransportVersion(authorization));
      const auto grpc_client = grpcClientFactory(authorization.grpc_service(), context);
      make_client = [grpc_client]() -> Authz::ClientPtr {
        return std::make_unique<BoundAuthorizationClient>(grpc_client(), "");
      };
    }
    const RecheckSettings settings(proto.recheck());
    auto scope = context.scope().createScope(prefix + "openzta.continuous_authz.");
    const auto resource_host = proto.resource_host();
    return [config, make_client, &context, settings, scope, resource_host](Http::FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamFilter(std::make_shared<HttpContinuousAuthz>(
        config, make_client(), make_client(), context, settings, scope, resource_host));
    };
  }
};

class NetworkFactory final : public NetworkFilters::Common::FactoryBase<Api::NetworkContinuousAuthz> {
public:
  NetworkFactory()
      : FactoryBase("openzta.filters.network.continuous_authz") {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
    const Api::NetworkContinuousAuthz& proto,
    Server::Configuration::FactoryContext& context) override {
    auto authorization = proto.authorization();
    if (authorization.failure_mode_allow() || authorization.has_filter_enabled_metadata()) {
      throw EnvoyException("continuous_authz network authorization cannot fail open or be bypassed");
    }
    authorization.set_include_peer_certificate(true);
    auto& server = context.serverFactoryContext();
    THROW_IF_NOT_OK(Config::Utility::checkTransportVersion(authorization));
    const auto config = std::make_shared<NetworkFilters::ExtAuthz::Config>(authorization, context.scope(), server);
    const auto make_client = grpcClientFactory(authorization.grpc_service(), server);
    const RecheckSettings settings(proto.recheck());
    auto scope = context.scope().createScope(authorization.stat_prefix() + ".openzta.continuous_authz.");
    return [config, make_client, &server, settings, scope](Network::FilterManager& manager) {
      manager.addReadFilter(std::make_shared<NetworkContinuousAuthz>(
        config, make_client(), make_client(), server.api().randomGenerator(), settings, scope));
    };
  }
};

REGISTER_FACTORY(HttpFactory, Server::Configuration::NamedHttpFilterConfigFactory);
REGISTER_FACTORY(NetworkFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace
} // namespace Envoy::Extensions::OpenZTA
