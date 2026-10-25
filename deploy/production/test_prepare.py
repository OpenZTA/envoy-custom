import copy,json,pathlib,unittest
from prepare import inspect_profile,references,mappings

class ProfileValidation(unittest.TestCase):
 def setUp(self):self.p=json.loads((pathlib.Path(__file__).parent/'example.json').read_text())
 def http(self):return self.p['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']
 def auth(self):return self.http()['http_filters'][0]['typed_config']
 def test_valid_profile(self):self.assertEqual(inspect_profile(self.p),[(8443,'tcp'),(8443,'udp')])
 def test_rejects_unreviewed_default_filter_chain(self):
  self.p['static_resources']['listeners'][0]['default_filter_chain']={'filters':[{'name':'envoy.filters.network.echo'}]}
  with self.assertRaisesRegex(ValueError,'default or dynamic filter chains'):inspect_profile(self.p)
 def test_rejects_dynamic_filter_chain_selection(self):
  self.p['static_resources']['listeners'][0]['filter_chain_matcher']={'matcher_tree':{}}
  with self.assertRaisesRegex(ValueError,'default or dynamic filter chains'):inspect_profile(self.p)
 def test_rejects_nac_without_service_identity(self):
  c=next(c for c in self.p['static_resources']['clusters'] if c['name']=='ext_authz');del c['transport_socket']['typed_config']['common_tls_context']['tls_certificates']
  with self.assertRaisesRegex(ValueError,'authenticate the proxy service'):inspect_profile(self.p)
 def test_rejects_network_filter_before_http_authorization(self):
  self.p['static_resources']['listeners'][0]['filter_chains'][0]['filters'].insert(0,{'name':'envoy.filters.network.echo'})
  with self.assertRaisesRegex(ValueError,'every network application filter'):inspect_profile(self.p)
 def test_rejects_exposed_administration(self):
  self.p['admin']['address']={'socket_address':{'address':'0.0.0.0','port_value':9901}}
  with self.assertRaisesRegex(ValueError,'Unix socket'):inspect_profile(self.p)
 def test_rejects_fail_open(self):
  self.auth()['authorization']['failure_mode_allow']=True
  with self.assertRaisesRegex(ValueError,'fail closed'):inspect_profile(self.p)
 def test_rejects_missing_identity(self):
  self.p['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config']['require_client_certificate']=False
  with self.assertRaisesRegex(ValueError,'mTLS'):inspect_profile(self.p)
 def test_rejects_disabled_recheck(self):
  self.auth()['recheck']['interval']='0s'
  with self.assertRaisesRegex(ValueError,'recheck'):inspect_profile(self.p)
 def test_rejects_delayed_recheck(self):
  self.auth()['recheck']['interval']='120s'
  with self.assertRaisesRegex(ValueError,'recheck'):inspect_profile(self.p)
 def test_rejects_route_bypass(self):
  self.http()['route_config']['virtual_hosts'][0]['routes'][0]['typed_per_filter_config']={'openzta.filters.http.continuous_authz':{'disabled':True}}
  with self.assertRaisesRegex(ValueError,'per-route'):inspect_profile(self.p)
 def test_rejects_original_destination(self):
  self.p['static_resources']['clusters'][0]['type']='ORIGINAL_DST'
  with self.assertRaisesRegex(ValueError,'unrestricted'):inspect_profile(self.p)
 def test_rejects_raw_udp(self):
  self.p['static_resources']['listeners'].append({'address':{'socket_address':{'port_value':9005,'protocol':'UDP'}}})
  with self.assertRaisesRegex(ValueError,'raw UDP'):inspect_profile(self.p)
 def test_rejects_unverified_nac(self):
  c=next(c for c in self.p['static_resources']['clusters'] if c['name']=='ext_authz');del c['transport_socket']
  with self.assertRaisesRegex(ValueError,'CA and SAN'):inspect_profile(self.p)
 def test_rejects_multiple_wt_sessions_on_one_upstream_connection(self):
  c=next(c for c in self.p['static_resources']['clusters'] if c['name']=='webtransport_upstream');c['typed_extension_protocol_options']['envoy.extensions.upstreams.http.v3.HttpProtocolOptions']['common_http_protocol_options']['max_requests_per_connection']=10
  with self.assertRaisesRegex(ValueError,'one session'):inspect_profile(self.p)
 def test_private_keys_are_external(self):
  with self.assertRaisesRegex(ValueError,'external files'):references({'private_key':{'inline_string':'secret'}})
 def test_mount_inventory_excludes_unreferenced_ca_keys(self):
  files=references(self.p);self.assertIn('/pki/gateway.key',files);self.assertNotIn('/pki/ca.key',files);self.assertEqual(len(files),5)
 def test_no_duplicate_port_mapping(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):mappings(['8443=443','8443=1443'])
 def test_rejects_forged_proxy_destination(self):
  self.p['static_resources']['listeners'][0]['listener_filters']=[{'name':'envoy.filters.listener.proxy_protocol'}]
  with self.assertRaisesRegex(ValueError,'trusted-L4'):inspect_profile(self.p)
 def test_rejects_accept_untrusted_downstream(self):
  self.p['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config']['common_tls_context']['validation_context']['trust_chain_verification']='ACCEPT_UNTRUSTED'
  with self.assertRaisesRegex(ValueError,'chain and validity'):inspect_profile(self.p)
 def test_rejects_accept_untrusted_nac(self):
  c=next(c for c in self.p['static_resources']['clusters'] if c['name']=='ext_authz');c['transport_socket']['typed_config']['common_tls_context']['validation_context']['trust_chain_verification']='ACCEPT_UNTRUSTED'
  with self.assertRaisesRegex(ValueError,'chain and validity'):inspect_profile(self.p)
 def test_rejects_filter_before_authorization(self):
  self.http()['http_filters'].insert(0,{'name':'envoy.filters.http.lua'})
  with self.assertRaisesRegex(ValueError,'every application filter'):inspect_profile(self.p)
 def test_rejects_inactive_webtransport_runtime(self):
  self.p['layered_runtime']['layers'][0]['static_layer']['envoy.reloadable_features.quic_support_web_transport']=False
  with self.assertRaisesRegex(ValueError,'runtime flags'):inspect_profile(self.p)
if __name__=='__main__':unittest.main()
