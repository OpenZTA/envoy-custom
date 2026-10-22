#pragma once

#include <functional>

#include "api/extensions/filters/continuous_authz/continuous_authz.pb.h"
#include "envoy/api/api.h"
#include "envoy/event/dispatcher.h"
#include "envoy/stats/scope.h"
#include "source/extensions/filters/common/ext_authz/ext_authz.h"

namespace Envoy::Extensions::OpenZTA {

namespace Authz = Filters::Common::ExtAuthz;
namespace Api = openzta::extensions::filters::continuous_authz::v1;

struct RecheckSettings {
  explicit RecheckSettings(const Api::Recheck& config);
  std::chrono::milliseconds interval;
  std::chrono::milliseconds jitter;
  std::chrono::milliseconds max_lifetime;
};

struct RecheckStats {
  explicit RecheckStats(Stats::Scope& scope);
  Stats::Counter& checks;
  Stats::Counter& allowed;
  Stats::Counter& denied;
  Stats::Counter& errors;
  Stats::Counter& expired;
  Stats::Gauge& active;
};

// Each controller is owned by one HTTP stream or network connection, and runs
// only on that connection's dispatcher. Cancellation precedes owner destruction.
class RecheckController final : public Authz::RequestCallbacks {
public:
  using Close = std::function<void(absl::string_view)>;
  RecheckController(Event::Dispatcher& dispatcher, Random::RandomGenerator& random,
                    StreamInfo::StreamInfo& info, Authz::ClientPtr client,
                    RecheckSettings settings, RecheckStats stats, Close close);
  ~RecheckController() override;
  void start(envoy::service::auth::v3::CheckRequest request);
  void stop();
  void onComplete(Authz::ResponsePtr&& response) override;

private:
  void schedule();
  void check();
  void expire();
  Random::RandomGenerator& random_;
  StreamInfo::StreamInfo& info_;
  Authz::ClientPtr client_;
  const RecheckSettings settings_;
  RecheckStats stats_;
  Close close_;
  Event::TimerPtr timer_;
  Event::TimerPtr lifetime_timer_;
  envoy::service::auth::v3::CheckRequest request_;
  bool active_{false};
  bool in_flight_{false};
};

} // namespace Envoy::Extensions::OpenZTA
