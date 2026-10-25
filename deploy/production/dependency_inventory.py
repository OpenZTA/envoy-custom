#!/usr/bin/env python3
"""Produce a CycloneDX build dependency inventory from pinned metadata and Bazel's actual graph."""
import argparse,ast,hashlib,json,pathlib,re
from urllib.parse import quote

def evaluate(node,values):
 if isinstance(node,ast.Constant):return node.value
 if isinstance(node,ast.Name):return values[node.id]
 if isinstance(node,(ast.List,ast.Tuple)):return [evaluate(x,values) for x in node.elts]
 if isinstance(node,ast.Dict):return {evaluate(k,values):evaluate(v,values) for k,v in zip(node.keys,node.values)}
 if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='dict' and not node.args:return {kw.arg:evaluate(kw.value,values) for kw in node.keywords}
 if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):return evaluate(node.left,values)+evaluate(node.right,values)
 raise ValueError('unsupported metadata expression: '+ast.dump(node)[:120])

def read_metadata(path):
 values={}
 for node in ast.parse(path.read_text()).body:
  if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
   try:values[node.targets[0].id]=evaluate(node.value,values)
   except (KeyError,ValueError):pass
 return values.get('REPOSITORY_LOCATIONS_SPEC',values.get('REPOSITORY_LOCATIONS',{}))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--query',required=True,help='output of bazel cquery deps(//:envoy), with the accepted build configuration');p.add_argument('--metadata',action='append',required=True,help='repository_locations.bzl from the resolved, patched build');p.add_argument('--workspace',required=True);p.add_argument('--build-evidence',required=True,help='packaging report with the compiled image and native input/patch hashes');p.add_argument('--out',required=True);args=p.parse_args()
 query=pathlib.Path(args.query);repos=set(re.findall(r'@+([^/@\s]+)//',query.read_text()));components=[];seen=set();matched=set();hashes={}
 for name in args.metadata:
  path=pathlib.Path(name);hashes[path.name+':'+hashlib.sha256(path.read_bytes()).hexdigest()]=hashlib.sha256(path.read_bytes()).hexdigest()
  for repository,entry in read_metadata(path).items():
   if repository not in repos:continue
   matched.add(repository);version=entry.get('version');project=entry.get('project_name',repository)
   if not version:continue
   ref='pkg:generic/'+quote(repository,safe='')+'@'+quote(version,safe='')
   if ref in seen:continue
   seen.add(ref);component={'type':'library','name':project,'version':version,'purl':ref,'bom-ref':ref,'properties':[{'name':'openzta:bazel_repository','value':repository},{'name':'openzta:use_category','value':','.join(entry.get('use_category',[]))}]}
   if entry.get('sha256'):component['hashes']=[{'alg':'SHA-256','content':entry['sha256']}]
   if entry.get('license'):component['licenses']=[{'license':{'name':entry['license']}}]
   if entry.get('project_url'):component['externalReferences']=[{'type':'website','url':entry['project_url']}]
   components.append(component)
 workspace=pathlib.Path(args.workspace);text=workspace.read_text()
 build=json.loads(pathlib.Path(args.build_evidence).read_text())
 if build.get('state')!='passed' or not re.fullmatch(r'sha256:[0-9a-f]{64}',build.get('image_id','')) or not build.get('native_input_hashes') or not build.get('native_patch_hashes'):raise ValueError('compiled image evidence and complete native input hashes are required')
 if build['native_input_hashes'].get('WORKSPACE')!=hashlib.sha256(workspace.read_bytes()).hexdigest():raise ValueError('dependency graph WORKSPACE differs from compiled input')
 root=workspace.parent
 for name,digest in build['native_patch_hashes'].items():
  if not (root/name).is_file() or hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('dependency graph patches differ from compiled input: '+name)
 for identifier,repository in [('envoy_version','envoy'),('openssh_version','openssh_portable'),('magic_enum_version','magic_enum'),('readerwriterqueue_version','readerwriterqueue')]:
  match=re.search(r'^'+identifier+r' = "([^\"]+)"',text,re.M)
  if match and repository in repos:
   ref='pkg:generic/'+repository+'@'+quote(match[1],safe='');components.append({'type':'library','name':repository,'version':match[1],'purl':ref,'bom-ref':ref});matched.add(repository)
 # Build rules, generated API repositories and compiler toolchains do not all
 # have release metadata. Keep the full graph list so coverage stays explicit.
 report={'state':'passed','image_id':build['image_id'],'native_patch_hashes':build['native_patch_hashes'],'native_input_hashes':build['native_input_hashes'],'scope':'resolved build dependency graph; includes build tools as labelled by upstream metadata','query_sha256':hashlib.sha256(query.read_bytes()).hexdigest(),'workspace_sha256':hashlib.sha256(workspace.read_bytes()).hexdigest(),'metadata_hashes':hashes,'resolved_repositories':sorted(repos),'matched_repositories':sorted(matched),'unmapped_repositories':sorted(repos-matched),'components':sorted(components,key=lambda x:x['bom-ref'])}
 if not components:raise ValueError('no dependencies matched the actual Bazel graph')
 pathlib.Path(args.out).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'state':'passed','components':len(components),'matched_repositories':len(matched),'unmapped_repositories':sorted(repos-matched)}))
if __name__=='__main__':main()
