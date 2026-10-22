#include "source/extensions/filters/continuous_authz/network.h"

#include "source/common/tracing/null_span_impl.h"
#include "source/common/common/logger.h"
#include "source/common/stream_info/bool_accessor_impl.h"
#include "source/extensions/filters/common/ext_authz/check_request_utils.h"

namespace Envoy::Extensions::OpenZTA {

NetworkContinuousAuthz::NetworkContinuousAuthz(
  NetworkFilters::ExtAuthz::ConfigSharedPtr config, Authz::ClientPtr initial_client,
  Authz::ClientPtr recheck_client, Random::RandomGenerator& random, RecheckSettings settings,
  Stats::ScopeSharedPtr scope)
    : config_(std::move(config)), initial_client_(std::move(initial_client)),
      recheck_client_(std::move(recheck_client)), random_(random), settings_(settings),
      scope_(std::move(scope)) {}

NetworkContinuousAuthz::~NetworkContinuousAuthz() {
  if (controller_) {
    controller_->stop();
  }
  if (in_flight_) {
    initial_client_->cancel();
    config_->stats().active_.dec();
  }
}

void NetworkContinuousAuthz::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
  // tcp_proxy otherwise disables transport reads during its initialization,
  // before onNewConnection() reaches this gate. Keep the TLS handshake readable
  // while holding the filter chain; no application bytes reach tcp_proxy until
  // authorization succeeds. This also allows server-first protocols to start.
  auto& state = *callbacks.connection().streamInfo().filterState();
  constexpr absl::string_view key = "envoy.tcp_proxy.receive_before_connect";
  if (state.hasDataWithName(key)) {
    const auto* value = state.getDataReadOnly<StreamInfo::BoolAccessor>(key);
    read_setup_valid_ = value != nullptr && value->value();
  } else {
    state.setData(key, std::make_shared<StreamInfo::BoolAccessorImpl>(true),
                  StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);
  }
  callbacks.connection().addConnectionCallbacks(*this);
  controller_ = std::make_unique<RecheckController>(
    callbacks.connection().dispatcher(), random_, callbacks.connection().streamInfo(),
    std::move(recheck_client_), settings_, RecheckStats(*scope_),
    [this](absl::string_view reason) { revoke(reason); });
}

Network::FilterStatus NetworkContinuousAuthz::onNewConnection() {
  if (!read_setup_valid_) {
    revoke("openzta_incompatible_tcp_filter_state");
    return Network::FilterStatus::StopIteration;
  }
  // Gate the upstream connection, including server-first protocols such as SMTP.
  // TLS must finish before the peer certificate can be sent to authorization.
  auto ssl = callbacks_->connection().ssl();
  if (!ssl || ssl->peerCertificatePresented()) {
    startCheck();
  }
  return authorized_ ? Network::FilterStatus::Continue : Network::FilterStatus::StopIteration;
}

Network::FilterStatus NetworkContinuousAuthz::onData(Buffer::Instance&, bool) {
  if (!started_) {
    startCheck();
  }
  return authorized_ ? Network::FilterStatus::Continue : Network::FilterStatus::StopIteration;
}

void NetworkContinuousAuthz::startCheck() {
  if (started_ || closed_) {
    return;
  }
  started_ = true;
  const auto ssl = callbacks_->connection().ssl();
  if (!ssl || !ssl->peerCertificateValidated()) {
    revoke("openzta_unverified_client_certificate");
    return;
  }
  Authz::CheckRequestUtils::createTcpCheck(callbacks_, snapshot_, true,
                                           config_->includeTLSSession(), config_->destinationLabels(), {});
  if (snapshot_.attributes().source().certificate().empty()) {
    revoke("openzta_client_certificate_required");
    return;
  }
  auto* extensions = snapshot_.mutable_attributes()->mutable_context_extensions();
  const std::string session_id = fmt::format("{:016x}{:016x}", random_.random(), random_.random());
  (*extensions)["openzta.session_id"] = session_id;
  Protobuf::Struct metadata;
  (*metadata.mutable_fields())["session_id"].set_string_value(session_id);
  callbacks_->connection().streamInfo().setDynamicMetadata("openzta.continuous_authz", metadata);
  (*extensions)["openzta.phase"] = "start";
  in_flight_ = true;
  config_->stats().active_.inc();
  config_->stats().total_.inc();
  calling_ = true;
  initial_client_->check(*this, snapshot_, Tracing::NullSpan::instance(),
                         callbacks_->connection().streamInfo());
  calling_ = false;
}

void NetworkContinuousAuthz::onComplete(Authz::ResponsePtr&& response) {
  in_flight_ = false;
  config_->stats().active_.dec();
  if (closed_) {
    return;
  }
  if (!response || response->status != Authz::CheckStatus::OK) {
    if (response && response->status == Authz::CheckStatus::Denied) {
      config_->stats().denied_.inc();
    } else {
      config_->stats().error_.inc();
    }
    revoke(response && response->status == Authz::CheckStatus::Denied
             ? "openzta_initial_authorization_denied"
             : "openzta_authorization_unavailable");
    return;
  }
  config_->stats().ok_.inc();
  authorized_ = true;
  controller_->start(snapshot_);
  if (!calling_) {
    callbacks_->continueReading();
  }
}

void NetworkContinuousAuthz::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected) {
    startCheck();
    return;
  }
  if (event == Network::ConnectionEvent::LocalClose || event == Network::ConnectionEvent::RemoteClose) {
    closed_ = true;
    controller_->stop();
    if (in_flight_) {
      in_flight_ = false;
      initial_client_->cancel();
      config_->stats().active_.dec();
    }
  }
}

void NetworkContinuousAuthz::revoke(absl::string_view reason) {
  if (closed_) {
    return;
  }
  authorized_ = false;
  closed_ = true;
  controller_->stop();
  config_->stats().cx_closed_.inc();
  callbacks_->connection().streamInfo().setResponseFlag(
    StreamInfo::CoreResponseFlag::UnauthorizedExternalService);
  callbacks_->connection().streamInfo().setResponseCodeDetails(reason);
  const auto& extensions = snapshot_.attributes().context_extensions();
  const auto session = extensions.find("openzta.session_id");
  ENVOY_LOG_MISC(info, "OpenZTA TCP authorization closed: session_id={} connection_id={} reason={}",
                 session == extensions.end() ? absl::string_view("-") : absl::string_view(session->second),
                 callbacks_->connection().id(), reason);
  callbacks_->connection().close(Network::ConnectionCloseType::AbortReset, reason);
}

} // namespace Envoy::Extensions::OpenZTA
