#!/usr/bin/env python3
"""Export an already accepted immutable native image, SBOM and verification evidence."""
import argparse,datetime,hashlib,json,pathlib,re,subprocess,uuid
from urllib.parse import quote

def run(args):return subprocess.check_output(args,text=True).strip()
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True);p.add_argument('--evidence',required=True);p.add_argument('--dependencies',required=True,help='Bazel dependency inventory emitted after the accepted build');p.add_argument('--out',required=True);p.add_argument('--cpp-status',choices=['passed','deferred'],required=True);args=p.parse_args()
 if not re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})',args.image):raise ValueError('immutable image digest is required')
 info=json.loads(run(['docker','image','inspect',args.image]))[0];evidence=json.loads(pathlib.Path(args.evidence).read_text());dependencies=json.loads(pathlib.Path(args.dependencies).read_text())
 if evidence.get('state')!='passed' or evidence.get('image_id')!=info['Id'] or not evidence.get('results') or any(r.get('state')!='passed' for r in evidence['results']):raise ValueError('passing runtime evidence for this exact image is required')
 if dependencies.get('state')!='passed' or not dependencies.get('components') or dependencies.get('image_id')!=info['Id']:raise ValueError('build dependency inventory for this exact image is required')
 cpp_label=info.get('Config',{}).get('Labels',{}).get('ru.openzta.verification.cpp');
 if cpp_label and cpp_label!=args.cpp_status:raise ValueError('C++ verification status disagrees with image label')
 root=pathlib.Path(__file__).resolve().parents[2];workspace=root/'WORKSPACE';expected_patches={name:sha(root/name) for name in re.findall(r'"//(patches/[^:]+):([^\"]+)"',workspace.read_text()) for name in [name[0]+'/'+name[1]]}
 if evidence.get('native_patch_hashes')!=expected_patches:raise ValueError('runtime evidence does not match current native patches')
 paths=[root/'WORKSPACE',root/'.bazelrc',root/'BUILD',*sorted((root/'source').rglob('*')),*sorted((root/'api').rglob('*'))]
 native_inputs={str(path.relative_to(root)):sha(path) for path in paths if path.is_file()}
 if evidence.get('native_input_hashes')!=native_inputs:raise ValueError('runtime evidence does not match current native source inputs')
 if dependencies.get('native_input_hashes')!=native_inputs or dependencies.get('native_patch_hashes')!=expected_patches:raise ValueError('dependency inventory does not match accepted native source inputs')
 out=pathlib.Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
 artifact=out/'openzta-proxy-image.tar'
 with artifact.open('wb') as stream:subprocess.run(['docker','save',args.image],stdout=stream,check=True)
 binary=run(['docker','run','--rm','--network','none','--read-only','--entrypoint','sha256sum',args.image,'/usr/local/bin/envoy']).split()[0]
 version=run(['docker','run','--rm','--network','none',args.image,'--version'])
 packages=run(['docker','run','--rm','--network','none','--read-only','--entrypoint','dpkg-query',args.image,'-W','-f','${Package}\t${Version}\t${Architecture}\n'])
 components=[{'type':'application','name':'OpenZTA Proxy','version':info['Id'],'bom-ref':info['Id'],'hashes':[{'alg':'SHA-256','content':binary}]}]
 for line in packages.splitlines():
  name,version_string,arch=line.split('\t');purl=f'pkg:deb/ubuntu/{quote(name,safe="")}@{quote(version_string,safe="")}?arch={arch}&distro=ubuntu-24.04';components.append({'type':'library','name':name,'version':version_string,'purl':purl,'bom-ref':purl})
 components.extend(dependencies['components'])
 now=datetime.datetime.now(datetime.timezone.utc).isoformat();bom={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'timestamp':now,'component':components[0]},'components':components[1:]}
 (out/'sbom.cdx.json').write_text(json.dumps(bom,indent=2)+'\n');(out/'runtime-acceptance.json').write_text(json.dumps(evidence,indent=2)+'\n');(out/'build-dependencies.json').write_text(json.dumps(dependencies,indent=2)+'\n')
 for name in ['README.ru.md','prepare.py','example.json','OPERATIONS.ru.md']:
  source=pathlib.Path(__file__).parent/name
  if source.exists():(out/name).write_bytes(source.read_bytes())
 manifest={'at':now,'image_id':info['Id'],'repository_digests':info.get('RepoDigests',[]),'architecture':info['Architecture'],'os':info['Os'],'binary_sha256':binary,'binary_version':version,'cpp_suite':args.cpp_status,'runtime_acceptance':'passed','verified_cases':len(evidence['results']),'native_patch_hashes':expected_patches,'files':{f.name:sha(f) for f in sorted(out.iterdir()) if f.is_file()},'limits':evidence.get('limits',[]),'archive_format':'docker-save; offline restore with docker load','registry_push_performed':False}
 (out/'release-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'SHA256SUMS').write_text(''.join(sha(f)+'  '+f.name+'\n' for f in sorted(out.iterdir()) if f.is_file()))
 print(json.dumps({'state':'exported','image_id':info['Id'],'out':str(out),'cpp_suite':args.cpp_status,'files':len(list(out.iterdir()))},indent=2))
if __name__=='__main__':main()
