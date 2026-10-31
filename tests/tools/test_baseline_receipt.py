from pathlib import Path
import hashlib,json,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from baseline_receipt import require_baseline
class BaselineTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.compiler=self.root/'nyrac';self.compiler.write_bytes(b'accepted compiler');(self.root/'manifest.json').write_text('{}');self.sources={'http':{'http.ny':'fixed'}};self.row={'status':'passed','source_sha256':self.sources,'sdk_manifest_sha256':hashlib.sha256(b'{}').hexdigest(),'compiler_sha256':hashlib.sha256(b'accepted compiler').hexdigest()}
 def test_exact_complete_baseline_is_reusable(self):require_baseline(self.row,self.root,self.compiler,self.sources)
 def test_partial_or_different_source_is_rejected(self):
  self.row['status']='failed'
  with self.assertRaises(ValueError):require_baseline(self.row,self.root,self.compiler,self.sources)
  self.row['status']='passed'
  with self.assertRaises(ValueError):require_baseline(self.row,self.root,self.compiler,{'http':{'http.ny':'changed'}})
 def test_changed_tool_is_rejected_through_nested_baseline(self):
  wrapped={'status':'passed','source_sha256':self.sources,'base':self.row};self.compiler.write_bytes(b'substituted')
  with self.assertRaises(ValueError):require_baseline(wrapped,self.root,self.compiler,self.sources)
if __name__=='__main__':unittest.main()
