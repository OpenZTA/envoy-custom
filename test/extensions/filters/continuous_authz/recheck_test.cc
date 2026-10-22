#include "source/extensions/filters/continuous_authz/recheck.h"
#include "envoy/common/exception.h"
#include "source/common/stats/isolated_store_impl.h"
#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/common.h"
#include "test/mocks/stream_info/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::OpenZTA {
namespace {
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

class RecheckTest : public testing::Test {
protected:
  void SetUp() override {
    timer_ = new NiceMock<Event::MockTimer>();
    lifetime_ = new NiceMock<Event::MockTimer>();
    EXPECT_CALL(dispatcher_, createTimer_(_))
      .WillOnce(Invoke([this](Event::TimerCb cb) {
        timer_->callback_ = std::move(cb);
        return timer_;
      }))
      .WillOnce(Invoke([this](Event::TimerCb cb) {
        lifetime_->callback_ = std::move(cb);
        return lifetime_;
      }));
    auto client = std::make_unique<NiceMock<Authz::MockClient>>();
    client_ = client.get();
    Api::Recheck config;
    config.mutable_interval()->set_seconds(1);
    config.mutable_jitter()->set_seconds(0);
    config.mutable_max_session_duration()->set_seconds(5);
    controller_ = std::make_unique<RecheckController>(dispatcher_, random_, info_,
                                                      std::move(client), RecheckSettings(config), RecheckStats(*store_.rootScope()),
                                                      [this](absl::string_view reason) { closes_.emplace_back(reason); });
    (*request_.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers())["x-openzta-session-id"] = "server-generated-session";
    request_.mutable_attributes()->mutable_source()->set_certificate("original-certificate");
  }

  Authz::ResponsePtr result(Authz::CheckStatus status) {
    auto response = std::make_unique<Authz::Response>();
    response->status = status;
    return response;
  }
  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Random::MockRandomGenerator> random_;
  NiceMock<StreamInfo::MockStreamInfo> info_;
  Stats::IsolatedStoreImpl store_;
  Event::MockTimer* timer_{};
  Event::MockTimer* lifetime_{};
  Authz::MockClient* client_{};
  envoy::service::auth::v3::CheckRequest request_;
  std::vector<std::string> closes_;
  std::unique_ptr<RecheckController> controller_;
};

TEST_F(RecheckTest, RechecksIdleStreamUsingOriginalIdentityWithoutReplayingBody) {
  request_.mutable_attributes()->mutable_request()->mutable_http()->set_body("must-not-replay");
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& cb, const auto& request, auto&, const auto&) {
    EXPECT_EQ("original-certificate", request.attributes().source().certificate());
    EXPECT_EQ("recheck", request.attributes().context_extensions().at("openzta.phase"));
    EXPECT_EQ("true", request.attributes().request().http().headers().at("x-openzta-reauthorization"));
    EXPECT_TRUE(request.attributes().request().http().body().empty());
    cb.onComplete(result(Authz::CheckStatus::OK));
  }));
  timer_->callback_();
  EXPECT_TRUE(closes_.empty());
  EXPECT_EQ(1, store_.counterFromString("rechecks_allowed").value());
}

TEST_F(RecheckTest, DeniedPolicyClosesSessionWithoutClientTraffic) {
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& cb, const auto&, auto&, const auto&) {
    cb.onComplete(result(Authz::CheckStatus::Denied));
  }));
  timer_->callback_();
  EXPECT_EQ(std::vector<std::string>{"openzta_policy_revoked"}, closes_);
  EXPECT_EQ(0, store_.gaugeFromString("active_sessions", Stats::Gauge::ImportMode::Accumulate).value());
}

TEST_F(RecheckTest, TCPRechecksDoNotTurnIntoHTTPAuthorizationRequests) {
  request_.mutable_attributes()->mutable_request()->clear_http();
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& cb, const auto& request, auto&, const auto&) {
    EXPECT_FALSE(request.attributes().request().has_http());
    EXPECT_EQ("recheck", request.attributes().context_extensions().at("openzta.phase"));
    cb.onComplete(result(Authz::CheckStatus::OK));
  }));
  timer_->callback_();
  EXPECT_TRUE(closes_.empty());
}

TEST_F(RecheckTest, AuthorizationOutageFailsClosed) {
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& cb, const auto&, auto&, const auto&) {
    cb.onComplete(result(Authz::CheckStatus::Error));
  }));
  timer_->callback_();
  EXPECT_EQ(std::vector<std::string>{"openzta_authorization_unavailable"}, closes_);
}

TEST_F(RecheckTest, PendingCheckDoesNotOverlapAndIsCancelledAtDestruction) {
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).Times(1);
  timer_->callback_();
  timer_->callback_();
  EXPECT_CALL(*client_, cancel()).Times(1);
  controller_.reset();
}

TEST_F(RecheckTest, MaximumLifetimeCancelsPendingCheckAndClosesOnce) {
  controller_->start(request_);
  EXPECT_CALL(*client_, check(_, _, _, _)).Times(1);
  timer_->callback_();
  EXPECT_CALL(*client_, cancel()).Times(1);
  lifetime_->callback_();
  lifetime_->callback_();
  EXPECT_EQ(std::vector<std::string>{"openzta_session_expired"}, closes_);
}

TEST(RecheckSettingsTest, OnlyAnExplicitZeroDisablesTheLifetimeLimit) {
  Api::Recheck config;
  EXPECT_EQ(std::chrono::hours(24), RecheckSettings(config).max_lifetime);
  config.mutable_max_session_duration()->set_seconds(0);
  EXPECT_EQ(std::chrono::milliseconds(0), RecheckSettings(config).max_lifetime);
  config.mutable_max_session_duration()->set_nanos(1);
  EXPECT_THROW((void)RecheckSettings(config), EnvoyException);
}

TEST_F(RecheckTest, StopIsIdempotent) {
  controller_->start(request_);
  controller_->stop();
  controller_->stop();
  EXPECT_EQ(0, store_.gaugeFromString("active_sessions", Stats::Gauge::ImportMode::Accumulate).value());
}

} // namespace
} // namespace Envoy::Extensions::OpenZTA
