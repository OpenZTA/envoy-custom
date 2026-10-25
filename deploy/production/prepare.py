#!/usr/bin/env python3
"""Validate and prepare a native proxy deployment. Never generates trust or allow policies."""
import argparse,datetime,hashlib,ipaddress,json,math,pathlib,re,subprocess,sys

def require(ok,message):
 if not ok:raise ValueError(message)
def duration(value):
 require(isinstance(value,str) and re.fullmatch(r'\d+(?:\.\d+)?s',value),'duration must be expressed in seconds')
 return float(value[:-1])
def mappings(spec):
 result={}
 for item in spec:
  parts=item.split('=');require(len(parts)==2,'port mapping must be listener=public')
  inside,outside=map(int,parts);require(1<=inside<=65535 and 1<=outside<=65535,'invalid port')
  require(inside not in result,'duplicate listener port mapping');result[inside]=outside
 return result

def inspect_profile(profile):
 """Reject bypasses and unsupported raw transports before invoking Envoy validation."""
 require(not profile.get('dynamic_resources'),'this tool validates static bootstraps; dynamic control planes require their own validation')
 admin=profile.get('admin',{}).get('address',{})
 require(admin.get('pipe',{}).get('path') and not admin.get('socket_address'),'administration must use a local Unix socket')
 resources=profile.get('static_resources',{});listeners=resources.get('listeners',[]);clusters={c['name']:c for c in resources.get('clusters',[])}
 require(listeners and clusters,'listeners and upstream clusters are required')
 ports=set();auth_clusters=set();webtransport_clusters=set()
 for listener in listeners:
  require(not listener.get('default_filter_chain') and not listener.get('filter_chain_matcher'),'default or dynamic filter chains require separate deployment validation')
  require(not any(f.get('name') in ['envoy.filters.listener.proxy_protocol','envoy.filters.listener.original_dst'] for f in listener.get('listener_filters',[])),'test PROXY/original-destination listeners require separate trusted-L4 deployment validation')
  socket=listener.get('address',{}).get('socket_address',{});require(socket and socket.get('port_value'),'listeners must use explicit IP ports')
  ports.add((int(socket['port_value']),socket.get('protocol','TCP').lower()))
  chains=listener.get('filter_chains',[]);require(chains,'raw UDP forwarding bypasses resource policies; use authenticated CONNECT-UDP')
  for chain in chains:
   transport=chain.get('transport_socket',{}).get('typed_config',{});quic='downstream_tls_context' in transport
   tls=transport.get('downstream_tls_context',transport)
   require(tls.get('require_client_certificate') is True,'mandatory downstream mTLS is required')
   require(tls.get('disable_stateless_session_resumption') is True and tls.get('disable_stateful_session_resumption') is True,'resumption must not bypass fresh certificate verification')
   require(not quic or transport.get('enable_early_data') is False,'QUIC 0-RTT must be disabled')
   validation=tls.get('common_tls_context',{}).get('validation_context',{})
   require(validation.get('trusted_ca'),'client certificate CA is required')
   require(validation.get('trust_chain_verification','VERIFY_TRUST_CHAIN')=='VERIFY_TRUST_CHAIN' and not validation.get('allow_expired_certificate',False) and not validation.get('custom_validator_config'),'downstream certificate chain and validity verification are required')
   filters=chain.get('filters',[]);names=[f['name'] for f in filters]
   for f in filters:
    if 'http_connection_manager' not in f['name']:continue
    require(names[0]==f['name'],'HTTP connection manager must precede every network application filter')
    h=f['typed_config'];http_filters=h.get('http_filters',[]);hn=[x['name'] for x in http_filters]
    require('openzta.filters.http.continuous_authz' in hn and 'envoy.filters.http.router' in hn,'HTTP must use native continuous authorization before the router')
    require(hn[0]=='openzta.filters.http.continuous_authz','authorization must precede every application filter')
    a=next(x['typed_config'] for x in http_filters if x['name']=='openzta.filters.http.continuous_authz')
    require(a.get('resource_host'),'immutable resource_host binding is required')
    require(0<duration(a.get('recheck',{}).get('interval','15s'))<=60,'policy recheck interval must be 0..60 seconds')
    require(duration(a.get('recheck',{}).get('jitter','1s'))<=5,'recheck jitter exceeds 5 seconds')
    authorization=a.get('authorization',{});require(authorization.get('failure_mode_allow',False) is False,'authorization must fail closed')
    require(not any(k in authorization for k in ['filter_enabled','filter_enabled_metadata','with_request_body','clear_route_cache']),'authorization bypass/body buffering is prohibited')
    if 'http_service' in authorization:auth_clusters.add(authorization['http_service']['server_uri']['cluster'])
    else:auth_clusters.add(authorization['grpc_service']['envoy_grpc']['cluster_name'])
    require(h.get('forward_client_cert_details')=='SANITIZE_SET','client certificate assertions must be replaced from TLS')
    for host in h.get('route_config',{}).get('virtual_hosts',[]):
     require('openzta.filters.http.continuous_authz' not in host.get('typed_per_filter_config',{}),'per-host authorization overrides require separate review')
     for route in host.get('routes',[]):
      require('openzta.filters.http.continuous_authz' not in route.get('typed_per_filter_config',{}),'per-route authorization overrides require separate review')
      action=route.get('route',{});name=action.get('cluster')
      require(not action.get('cluster_header') and not action.get('cluster_specifier_plugin'),'caller-selected upstream is prohibited')
      if name:require(name in clusters,'unknown route cluster: '+name)
      if any(u.get('upgrade_type') in ['webtransport','webtransport-h3'] for u in action.get('upgrade_configs',[])):
       require(h.get('codec_type')=='HTTP3','WebTransport routes require HTTP/3')
       webtransport_clusters.add(name)
   if not any('http_connection_manager' in name for name in names):
    require('openzta.filters.network.continuous_authz' in names,'TCP must pass native continuous authorization')
    require(names[0]=='openzta.filters.network.continuous_authz','TCP authorization must precede every application filter')
    require('envoy.filters.network.tcp_proxy' in names and names.index('openzta.filters.network.continuous_authz')<names.index('envoy.filters.network.tcp_proxy'),'TCP authorization must precede forwarding')
    a=next(f['typed_config'] for f in filters if f['name']=='openzta.filters.network.continuous_authz');require(not a['authorization'].get('failure_mode_allow',False),'TCP authorization must fail closed')
    require(0<duration(a.get('recheck',{}).get('interval','15s'))<=60,'TCP recheck interval must be 0..60 seconds')
    auth_clusters.add(a['authorization']['grpc_service']['envoy_grpc']['cluster_name'])
 runtime={}
 for layer in profile.get('layered_runtime',{}).get('layers',[]):runtime.update(layer.get('static_layer',{}))
 if webtransport_clusters:require(runtime.get('envoy.reloadable_features.quic_support_web_transport') is True and runtime.get('envoy.reloadable_features.enable_universal_header_validator') is True,'WebTransport and universal header validation runtime flags must be enabled')
 for name,c in clusters.items():
  require(c.get('type')!='ORIGINAL_DST' and 'dynamic_forward_proxy' not in c.get('cluster_type',{}).get('name',''),'unrestricted forwarding cluster is prohibited')
 for name in auth_clusters|webtransport_clusters:
  c=clusters[name];tls=c.get('transport_socket',{}).get('typed_config',{});tls=tls.get('upstream_tls_context',tls)
  common=tls.get('common_tls_context',{});validation=common.get('validation_context',{})
  require(validation.get('trust_chain_verification','VERIFY_TRUST_CHAIN')=='VERIFY_TRUST_CHAIN' and not validation.get('allow_expired_certificate',False) and not validation.get('custom_validator_config'),'upstream certificate chain and validity verification are required')
  require(validation.get('trusted_ca') and validation.get('match_typed_subject_alt_names') and all(v.get('matcher',{}).get('exact') for v in validation['match_typed_subject_alt_names']),'authorization and WebTransport upstreams require CA and SAN verification: '+name)
  require(common.get('tls_certificates'),'authorization and WebTransport upstreams must authenticate the proxy service with mTLS: '+name)
  if name in webtransport_clusters:
   options=c.get('typed_extension_protocol_options',{}).get('envoy.extensions.upstreams.http.v3.HttpProtocolOptions',{})
   require('http3_protocol_options' in options.get('explicit_http_config',{}),'WebTransport upstream must explicitly use HTTP/3')
   require(options.get('common_http_protocol_options',{}).get('max_requests_per_connection')==1,'WebTransport must use one session per upstream QUIC connection')
 return sorted(ports)

def references(node,result=None):
 if result is None:result={}
 if isinstance(node,dict):
  for key,value in node.items():
   if key=='private_key':require(isinstance(value,dict) and set(value)=={'filename'},'private keys must be external files; inline key material is prohibited')
   if key in ['private_key','certificate_chain','trusted_ca','crl'] and isinstance(value,dict) and 'filename' in value:result[value['filename']]=key
   references(value,result)
 elif isinstance(node,list):
  for value in node:references(value,result)
 return result

def run(args,**kwargs):return subprocess.run(args,check=True,text=True,capture_output=True,**kwargs).stdout

def prepare(args):
 image=args.image;require(re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',image),'use an immutable image ID or repository@sha256 digest')
 require(args.uid>0 and args.gid>0,'runtime UID/GID must be non-root')
 ipaddress.ip_address(args.bind)
 source=pathlib.Path(args.bootstrap).resolve();source_text=source.read_text();require('PRIVATE KEY-----' not in source_text,'inline private key material is prohibited');profile=json.loads(source_text);ports=inspect_profile(profile)
 profile['admin']={'address':{'pipe':{'path':'/tmp/envoy-admin.sock'}}}
 profile.setdefault('overload_manager',{'refresh_interval':'0.25s','resource_monitors':[{'name':'envoy.resource_monitors.fixed_heap','typed_config':{'@type':'type.googleapis.com/envoy.extensions.resource_monitors.fixed_heap.v3.FixedHeapConfig','max_heap_size_bytes':args.heap_mb*1024*1024}}],'actions':[{'name':'envoy.overload_actions.stop_accepting_requests','triggers':[{'name':'envoy.resource_monitors.fixed_heap','threshold':{'value':0.95}}]},{'name':'envoy.overload_actions.disable_http_keepalive','triggers':[{'name':'envoy.resource_monitors.fixed_heap','threshold':{'value':0.90}}]}]})
 monitors=profile['overload_manager'].setdefault('resource_monitors',[])
 if not any(m.get('name')=='envoy.resource_monitors.global_downstream_max_connections' for m in monitors):monitors.append({'name':'envoy.resource_monitors.global_downstream_max_connections','typed_config':{'@type':'type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig','max_active_downstream_connections':args.max_connections}})
 require(args.memory_mb>=args.heap_mb+128 and args.heap_mb>=128,'container memory must exceed heap budget by at least 128 MiB')
 pki=pathlib.Path(args.pki).resolve();volumes=[];certificates=[]
 for target,kind in references(profile).items():
  path=pathlib.PurePosixPath(target);require(target.startswith('/pki/') and '..' not in path.parts,'TLS files must live below /pki/')
  host=pki.joinpath(*path.parts[2:]).resolve();require(host.is_relative_to(pki) and host.is_file(),'TLS reference escapes PKI directory or is missing: '+target)
  mode=host.stat().st_mode;require(not mode&0o022,'TLS material must not be writable by other users: '+target)
  if kind=='private_key':require(not mode&0o007,'private key must not be world-readable: '+target)
  elif kind in ['certificate_chain','trusted_ca']:
   run(['openssl','x509','-checkend',str(args.minimum_validity_hours*3600),'-noout','-in',str(host)])
   der=run(['openssl','x509','-noout','-fingerprint','-sha256','-in',str(host)]).strip();certificates.append({'file':target,'fingerprint':der})
  volumes.append({'type':'bind','source':str(host),'target':target,'read_only':True,'bind':{'create_host_path':False}})
 require(volumes,'no TLS files referenced')
 image_info=json.loads(run(['docker','image','inspect',image]))[0]
 protected=json.loads(run(['docker','network','inspect',args.protected_network]))[0];require(protected.get('Internal') is True,'protected backend network must be internal')
 run(['docker','network','inspect',args.edge_network])
 portmap=mappings(args.port_map);out=pathlib.Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
 bootstrap=out/'envoy.json';bootstrap.write_text(json.dumps(profile,indent=2)+'\n')
 volumes.insert(0,{'type':'bind','source':str(bootstrap),'target':'/etc/envoy/envoy.json','read_only':True,'bind':{'create_host_path':False}})
 # Validate the exact files with the runtime identity, without publishing ports.
 command=['docker','run','--rm','--network','none','--user',f'{args.uid}:{args.gid}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=32m']
 for v in volumes:command+=['--mount',f"type=bind,source={v['source']},target={v['target']},readonly"]
 run(command+[image,'--mode','validate','-c','/etc/envoy/envoy.json','--log-level','warning'])
 service={'image':image,'user':f'{args.uid}:{args.gid}','labels':{'ru.openzta.bootstrap.sha256':hashlib.sha256(bootstrap.read_bytes()).hexdigest()},'restart':'unless-stopped','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'tmpfs':['/tmp:rw,noexec,nosuid,size=32m'],'mem_limit':f'{args.memory_mb}m','cpus':args.cpus,'pids_limit':128,'stop_grace_period':'90s','sysctls':{'net.ipv4.ip_forward':'0','net.ipv6.conf.all.forwarding':'0'},'ulimits':{'nofile':{'soft':65536,'hard':65536}},'command':['-c','/etc/envoy/envoy.json','--concurrency',str(args.workers),'--drain-time-s','60','--log-level','info'],'volumes':volumes,'ports':[f'{chr(91)+args.bind+chr(93) if chr(58) in args.bind else args.bind}:{portmap.get(port,port)}:{port}/{protocol}' for port,protocol in ports],'networks':['edge','protected'],'logging':{'driver':'json-file','options':{'max-size':'20m','max-file':'5'}}}
 compose={'services':{'proxy':service},'networks':{'edge':{'external':True,'name':args.edge_network},'protected':{'external':True,'name':args.protected_network}}}
 (out/'compose.json').write_text(json.dumps(compose,indent=2)+'\n')
 manifest={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'configuration-validated','image_id':image_info['Id'],'architecture':image_info['Architecture'],'os':image_info['Os'],'bootstrap_sha256':hashlib.sha256(bootstrap.read_bytes()).hexdigest(),'uid':args.uid,'gid':args.gid,'ports':service['ports'],'certificates':certificates,'private_key_contents_copied':False,'only_referenced_TLS_files_mounted':True,'protected_network_internal':True,'full_cpp_suite':'not checked; not implied by configuration validation','runtime_acceptance':'required against the actual protected resource before rollout'}
 (out/'deployment-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bootstrap',required=True,help='static Envoy JSON bootstrap');p.add_argument('--pki',required=True,help='host directory corresponding to /pki');p.add_argument('--image',required=True);p.add_argument('--protected-network',required=True);p.add_argument('--edge-network',required=True);p.add_argument('--out',required=True);p.add_argument('--uid',type=int,default=10001);p.add_argument('--gid',type=int,default=10001);p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port-map',action='append',default=[]);p.add_argument('--workers',type=int,default=2);p.add_argument('--cpus',type=float,default=2);p.add_argument('--max-connections',type=int,default=256);p.add_argument('--memory-mb',type=int,default=1024);p.add_argument('--heap-mb',type=int,default=768);p.add_argument('--minimum-validity-hours',type=int,default=24)
 args=p.parse_args();require(1<=args.max_connections<=65535,'invalid downstream connection limit');require(1<=args.workers<=64 and math.isfinite(args.cpus) and args.cpus>0,'invalid worker/CPU limits');require(args.minimum_validity_hours>=1,'minimum certificate validity must be positive');prepare(args)
if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,subprocess.CalledProcessError) as e:
  print('Deployment preflight failed: '+str(e),file=sys.stderr)
  if isinstance(e,subprocess.CalledProcessError):print(e.stderr[-4000:] if e.stderr else '',file=sys.stderr)
  sys.exit(1)
