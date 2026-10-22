#include "source/extensions/filters/continuous_authz/recheck.h"

#include "envoy/common/exception.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tracing/null_span_impl.h"

namespace Envoy::Extensions::OpenZTA {

RecheckSettings::RecheckSettings(const Api::Recheck& config)
    : interval(PROTOBUF_GET_MS_OR_DEFAULT(config, interval, 15000)),
      jitter(PROTOBUF_GET_MS_OR_DEFAULT(config, jitter, 1000)),
      max_lifetime(PROTOBUF_GET_MS_OR_DEFAULT(config, max_session_duration, 86400000)) {
  if (interval.count() < 100 || interval > std::chrono::hours(1) ||
      jitter.count() < 0 || jitter > interval || max_lifetime.count() < 0 ||
      (config.has_jitter() && (config.jitter().seconds() < 0 || config.jitter().nanos() < 0)) ||
      (config.has_max_session_duration() && max_lifetime.count() == 0 &&
       (config.max_session_duration().seconds() != 0 || config.max_session_duration().nanos() != 0))) {
    throw EnvoyException("continuous_authz: invalid interval, jitter or session duration");
  }
}

RecheckStats::RecheckStats(Stats::Scope& scope)
    : checks(scope.counterFromString("rechecks")),
      allowed(scope.counterFromString("rechecks_allowed")),
      denied(scope.counterFromString("rechecks_denied")),
      errors(scope.counterFromString("rechecks_error")),
      expired(scope.counterFromString("sessions_expired")),
      active(scope.gaugeFromString("active_sessions", Stats::Gauge::ImportMode::Accumulate)) {}

RecheckController::RecheckController(Event::Dispatcher& dispatcher, Random::RandomGenerator& random,
                                     StreamInfo::StreamInfo& info, Authz::ClientPtr client,
                                     RecheckSettings settings, RecheckStats stats, Close close)
    : random_(random), info_(info), client_(std::move(client)),
      settings_(settings), stats_(stats), close_(std::move(close)),
      timer_(dispatcher.createTimer([this] { check(); })),
      lifetime_timer_(dispatcher.createTimer([this] { expire(); })) {}

RecheckController::~RecheckController() {
  stop();
}

void RecheckController::start(envoy::service::auth::v3::CheckRequest request) {
  if (active_) {
    return;
  }
  request_ = std::move(request);
  // Both clients understand phase metadata; HTTP clients additionally forward
  // this reserved header. It is set by the filter, never accepted from a peer.
  (*request_.mutable_attributes()->mutable_context_extensions())["openzta.phase"] = "recheck";
  if (request_.attributes().request().has_http()) {
    auto* http = request_.mutable_attributes()->mutable_request()->mutable_http();
    (*http->mutable_headers())["x-openzta-reauthorization"] = "true";
    http->clear_body();
    http->clear_raw_body();
  }
  active_ = true;
  stats_.active.inc();
  if (settings_.max_lifetime.count() > 0) {
    lifetime_timer_->enableTimer(settings_.max_lifetime);
  }
  schedule();
}

void RecheckController::schedule() {
  const auto jitter = settings_.jitter.count() == 0
                        ? 0
                        : random_.random() % (settings_.jitter.count() + 1);
  timer_->enableTimer(settings_.interval + std::chrono::milliseconds(jitter));
}

void RecheckController::check() {
  if (!active_ || in_flight_) {
    return;
  }
  in_flight_ = true;
  stats_.checks.inc();
  // check() may complete synchronously and the callback can destroy the owner.
  // Do not access any fields after calling the client.
  client_->check(*this, request_, Tracing::NullSpan::instance(), info_);
}

void RecheckController::stop() {
  timer_->disableTimer();
  lifetime_timer_->disableTimer();
  if (active_) {
    active_ = false;
    stats_.active.dec();
  }
  if (in_flight_) {
    in_flight_ = false;
    client_->cancel();
  }
}

void RecheckController::onComplete(Authz::ResponsePtr&& response) {
  in_flight_ = false;
  if (!active_) {
    return;
  }
  if (response && response->status == Authz::CheckStatus::OK) {
    stats_.allowed.inc();
    schedule();
    return;
  }
  const bool denied = response && response->status == Authz::CheckStatus::Denied;
  if (denied) {
    stats_.denied.inc();
  } else {
    stats_.errors.inc();
  }
  auto close = close_;
  stop();
  close(denied ? "openzta_policy_revoked" : "openzta_authorization_unavailable");
}

void RecheckController::expire() {
  if (!active_) {
    return;
  }
  stats_.expired.inc();
  auto close = close_;
  stop();
  close("openzta_session_expired");
}

} // namespace Envoy::Extensions::OpenZTA
