#include "source/extensions/filters/continuous_authz/http.h"
#include "source/common/network/address_impl.h"
#include "source/common/stats/isolated_store_impl.h"
#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/ssl/mocks.h"
#include "test/test_common/utility.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::OpenZTA {
namespace {
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

class HttpContinuousAuthzTest : public testing::Test {
protected:
  void SetUp() override {
    envoy::extensions::filters::http::ext_authz::v3::ExtAuthz proto;
    proto.mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("authz");
    proto.set_include_peer_certificate(true);
    auto config = std::make_shared<HttpFilters::ExtAuthz::FilterConfig>(proto, *store_.rootScope(), "test.", server_);
    auto initial = std::make_unique<NiceMock<Authz::MockClient>>();
    initial_ = initial.get();
    auto recheck = std::make_unique<NiceMock<Authz::MockClient>>();
    recheck_ = recheck.get();
    ssl_ = std::make_shared<NiceMock<Ssl::MockConnectionInfo>>();
    ON_CALL(connection_, ssl()).WillByDefault(Return(ssl_));
    ON_CALL(*ssl_, peerCertificatePresented()).WillByDefault(Return(true));
    ON_CALL(*ssl_, peerCertificateValidated()).WillByDefault(Return(true));
    ON_CALL(*ssl_, urlEncodedPemEncodedPeerCertificate()).WillByDefault(ReturnRef(certificate_));
    ON_CALL(decoder_, connection()).WillByDefault(Return(OptRef<const Network::Connection>{connection_}));
    auto address = std::make_shared<Network::Address::Ipv4Instance>("127.0.0.1", 8443);
    connection_.stream_info_.downstream_connection_info_provider_->setLocalAddress(address);
    connection_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(address);
    EXPECT_CALL(decoder_.dispatcher_, createTimer_(_)).Times(2).WillRepeatedly(Invoke([this](Event::TimerCb cb) {
      auto* timer = new NiceMock<Event::MockTimer>();
      timer->callback_ = std::move(cb);
      if (interval_timer_ == nullptr) {
        interval_timer_ = timer;
      }
      return timer;
    }));
    filter_ = std::make_unique<HttpContinuousAuthz>(config, std::move(initial), std::move(recheck), server_, RecheckSettings(Api::Recheck{}), store_.createScope("continuous."), "app.example");
    filter_->setDecoderFilterCallbacks(decoder_);
    filter_->setEncoderFilterCallbacks(encoder_);
  }
  void TearDown() override { filter_->onDestroy(); }
  Authz::ResponsePtr response(Authz::CheckStatus status) {
    auto result = std::make_unique<Authz::Response>();
    result->status = status;
    return result;
  }
  void allowInitial() {
    EXPECT_CALL(*initial_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& callbacks, const auto& request, auto&, const auto&) {
      initial_snapshot_ = request;
      EXPECT_EQ("app.example", request.attributes().request().http().headers().at("x-original-host"));
      callbacks.onComplete(response(Authz::CheckStatus::OK));
    }));
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  }
  void denyRecheck() {
    EXPECT_CALL(*recheck_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& callbacks, const auto& request, auto&, const auto&) {
      EXPECT_EQ(certificate_, request.attributes().source().certificate());
      const auto& headers = request.attributes().request().http().headers();
      EXPECT_EQ("true", headers.at("x-openzta-reauthorization"));
      EXPECT_EQ("app.example", headers.at("x-original-host"));
      EXPECT_EQ("/stream?q=1", headers.at("x-original-path"));
      EXPECT_EQ("GET", headers.at("x-original-method"));
      EXPECT_EQ(initial_snapshot_.attributes().request().http().headers().at("x-openzta-session-id"), headers.at("x-openzta-session-id"));
      callbacks.onComplete(response(Authz::CheckStatus::Denied));
    }));
    interval_timer_->callback_();
  }
  Stats::IsolatedStoreImpl store_;
  NiceMock<Server::Configuration::MockServerFactoryContext> server_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_;
  NiceMock<Network::MockConnection> connection_;
  std::shared_ptr<NiceMock<Ssl::MockConnectionInfo>> ssl_;
  const std::string certificate_{"authenticated-tls-certificate"};
  Authz::MockClient* initial_{};
  Authz::MockClient* recheck_{};
  Event::MockTimer* interval_timer_{};
  std::unique_ptr<HttpContinuousAuthz> filter_;
  envoy::service::auth::v3::CheckRequest initial_snapshot_;
  Http::TestRequestHeaderMapImpl headers_{{":method", "GET"}, {":path", "/stream?q=1"}, {":authority", "app.example"}, {":scheme", "https"}, {"x-forwarded-client-cert", "forged"}, {"x-original-host", "forged"}, {"x-original-method", "DELETE"}, {"x-original-path", "/forged"}, {"x-openzta-session-id", "forged"}, {"x-openzta-reauthorization", "true"}};
};

TEST_F(HttpContinuousAuthzTest, ResponseAlreadyStartedIsResetWithoutWritingAnotherResponse) {
  headers_.setHost("other-allowed-resource.example");
  allowInitial();
  const auto& trusted = initial_snapshot_.attributes().request().http().headers();
  EXPECT_EQ("Cert=\"authenticated-tls-certificate\"", trusted.at("x-forwarded-client-cert"));
  EXPECT_EQ(0, trusted.count("x-openzta-reauthorization"));
  EXPECT_NE("forged", trusted.at("x-openzta-session-id"));
  // Route/header mutation after initial authorization must not change the
  // authenticated identity or operation used by the periodic policy check.
  headers_.setHost("changed-upstream.example");
  headers_.setPath("/rewritten");
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}, {"content-type", "text/event-stream"}};
  filter_->encodeHeaders(response_headers, false);
  EXPECT_CALL(decoder_, sendLocalReply(_, _, _, _, _)).Times(0);
  EXPECT_CALL(decoder_, resetStream(Http::StreamResetReason::LocalReset, "openzta_policy_revoked"));
  denyRecheck();
}

TEST_F(HttpContinuousAuthzTest, RevocationBeforeResponseProducesOneForbiddenReply) {
  allowInitial();
  EXPECT_CALL(decoder_, resetStream(_, _)).Times(0);
  EXPECT_CALL(decoder_, sendLocalReply(Http::Code::Forbidden, _, _, _, "openzta_policy_revoked"));
  denyRecheck();
}

TEST_F(HttpContinuousAuthzTest, UnverifiedTLSCannotReachAuthorizationOrApplication) {
  ON_CALL(*ssl_, peerCertificateValidated()).WillByDefault(Return(false));
  EXPECT_CALL(*initial_, check(_, _, _, _)).Times(0);
  EXPECT_CALL(*recheck_, check(_, _, _, _)).Times(0);
  EXPECT_CALL(decoder_, sendLocalReply(Http::Code::Forbidden, _, _, _, "openzta_unverified_client_certificate"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
}

TEST_F(HttpContinuousAuthzTest, OutageBeforeResponseUsesUnavailableInsteadOfPolicyDenial) {
  allowInitial();
  EXPECT_CALL(decoder_, resetStream(_, _)).Times(0);
  EXPECT_CALL(decoder_, sendLocalReply(Http::Code::ServiceUnavailable, _, _, _, "openzta_authorization_unavailable"));
  EXPECT_CALL(*recheck_, check(_, _, _, _)).WillOnce(Invoke([this](Authz::RequestCallbacks& callbacks, const auto&, auto&, const auto&) {
    callbacks.onComplete(response(Authz::CheckStatus::Error));
  }));
  interval_timer_->callback_();
}
} // namespace
} // namespace Envoy::Extensions::OpenZTA
