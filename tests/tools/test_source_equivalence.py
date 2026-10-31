from pathlib import Path
import hashlib,subprocess,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from baseline_receipt import require_equivalent_sources
class SourceEquivalenceTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.file=self.root/'test.py';self.old='def generated():\n return "same program"\ndef main():\n pass\n';self.file.write_text(self.old)
  subprocess.run(['git','init','-q',self.root],check=True);subprocess.run(['git','-C',self.root,'add','.'],check=True);subprocess.run(['git','-C',self.root,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],check=True);self.commit=subprocess.check_output(['git','-C',self.root,'rev-parse','HEAD'],text=True).strip();self.inventory={'test.py':hashlib.sha256(self.old.encode()).hexdigest()}
 def test_only_orchestration_main_change_is_admitted(self):
  self.file.write_text(self.old.replace(' pass',' print("resume")'));self.assertTrue(require_equivalent_sources(self.inventory,self.root,self.commit)['protocol_generators_peers_equal'])
 def test_changed_generator_is_rejected(self):
  self.file.write_text(self.old.replace('same program','different program'))
  with self.assertRaises(ValueError):require_equivalent_sources(self.inventory,self.root,self.commit)
 def test_additional_language_input_is_rejected(self):
  (self.root/'extra.ny').write_text('func extra() {}')
  with self.assertRaises(ValueError):require_equivalent_sources(self.inventory,self.root,self.commit)
if __name__=='__main__':unittest.main()
