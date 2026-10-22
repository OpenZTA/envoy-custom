#include "source/extensions/filters/continuous_authz/network.h"
#include "source/common/network/address_impl.h"
#include "source/common/stats/isolated_store_impl.h"
#include "envoy/stream_info/bool_accessor.h"
#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/common.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/ssl/mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy::Extensions::OpenZTA {
namespace {
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

class NetworkContinuousAuthzTest : public testing::Test {
protected:
  void SetUp() override {
    envoy::extensions::filters::network::ext_authz::v3::ExtAuthz proto;
    proto.set_stat_prefix("test");
    proto.mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("authz");
    auto config = std::make_shared<NetworkFilters::ExtAuthz::Config>(proto, *store_.rootScope(), server_);
    auto initial = std::make_unique<NiceMock<Authz::MockClient>>();
    initial_ = initial.get();
    auto recheck = std::make_unique<NiceMock<Authz::MockClient>>();
    ssl_ = std::make_shared<NiceMock<Ssl::MockConnectionInfo>>();
    ON_CALL(callbacks_.connection_, ssl()).WillByDefault(Return(ssl_));
    ON_CALL(*ssl_, peerCertificatePresented()).WillByDefault(Return(false));
    ON_CALL(*ssl_, peerCertificateValidated()).WillByDefault(Return(true));
    ON_CALL(*ssl_, urlEncodedPemEncodedPeerCertificate()).WillByDefault(ReturnRef(certificate_));
    auto address = std::make_shared<Network::Address::Ipv4Instance>("127.0.0.1", 2222);
    callbacks_.connection_.stream_info_.downstream_connection_info_provider_->setLocalAddress(address);
    callbacks_.connection_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(address);
    filter_ = std::make_unique<NetworkContinuousAuthz>(config, std::move(initial), std::move(recheck),
                                                       random_, RecheckSettings(Api::Recheck{}), store_.createScope("continuous."));
    EXPECT_CALL(callbacks_.connection_.dispatcher_, createTimer_(_)).Times(2).WillRepeatedly(Invoke([](Event::TimerCb cb) {
      auto* timer = new NiceMock<Event::MockTimer>();
      timer->callback_ = std::move(cb);
      return timer;
    }));
    filter_->initializeReadFilterCallbacks(callbacks_);
  }
  Authz::ResponsePtr response(Authz::CheckStatus status) {
    auto r = std::make_unique<Authz::Response>();
    r->status = status;
    return r;
  }
  Stats::IsolatedStoreImpl store_;
  NiceMock<Server::Configuration::MockServerFactoryContext> server_;
  NiceMock<Network::MockReadFilterCallbacks> callbacks_;
  NiceMock<Random::MockRandomGenerator> random_;
  std::shared_ptr<NiceMock<Ssl::MockConnectionInfo>> ssl_;
  const std::string certificate_{"authenticated-tls-certificate"};
  Authz::MockClient* initial_{};
  std::unique_ptr<NetworkContinuousAuthz> filter_;
};

TEST_F(NetworkContinuousAuthzTest, TLSHandshakeRemainsReadableWhileUpstreamIsGated) {
  const auto* state = callbacks_.connection_.stream_info_.filterState()
                        ->getDataReadOnly<StreamInfo::BoolAccessor>("envoy.tcp_proxy.receive_before_connect");
  ASSERT_NE(nullptr, state);
  EXPECT_TRUE(state->value());
  EXPECT_CALL(*initial_, check(_, _, _, _)).Times(0);
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  testing::Mock::VerifyAndClearExpectations(initial_);
  ON_CALL(*ssl_, peerCertificatePresented()).WillByDefault(Return(true));
  Authz::RequestCallbacks* pending{};
  EXPECT_CALL(*initial_, check(_, _, _, _)).WillOnce(Invoke([&](Authz::RequestCallbacks& cb, const auto& request, auto&, const auto&) {
    pending = &cb;
    EXPECT_EQ(certificate_, request.attributes().source().certificate());
    EXPECT_EQ("start", request.attributes().context_extensions().at("openzta.phase"));
  }));
  EXPECT_CALL(callbacks_, continueReading()).Times(0);
  filter_->onEvent(Network::ConnectionEvent::Connected);
  ASSERT_NE(nullptr, pending);
  testing::Mock::VerifyAndClearExpectations(&callbacks_);
  EXPECT_CALL(callbacks_, continueReading()).Times(1);
  pending->onComplete(response(Authz::CheckStatus::OK));
}

TEST_F(NetworkContinuousAuthzTest, InitialDenyNeverContinuesToServerFirstUpstream) {
  ON_CALL(*ssl_, peerCertificatePresented()).WillByDefault(Return(true));
  EXPECT_CALL(*initial_, check(_, _, _, _)).WillOnce(Invoke([&](Authz::RequestCallbacks& cb, const auto&, auto&, const auto&) {
    cb.onComplete(response(Authz::CheckStatus::Denied));
  }));
  EXPECT_CALL(callbacks_, continueReading()).Times(0);
  EXPECT_CALL(callbacks_.connection_, close(Network::ConnectionCloseType::AbortReset, _));
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
}

TEST_F(NetworkContinuousAuthzTest, DisconnectCancelsInitialCheckOnce) {
  ON_CALL(*ssl_, peerCertificatePresented()).WillByDefault(Return(true));
  EXPECT_CALL(*initial_, check(_, _, _, _)).Times(1);
  EXPECT_CALL(*initial_, cancel()).Times(1);
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  filter_->onEvent(Network::ConnectionEvent::RemoteClose);
  filter_.reset();
}
} // namespace
} // namespace Envoy::Extensions::OpenZTA
