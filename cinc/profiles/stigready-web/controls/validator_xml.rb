# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready-web#57: scripts/validate-site.py parses the repository's XML/SVG, which in a pull request run is the pull
# request's own. It must parse with defusedxml (semgrep python.lang.security.use-defused-xml-parse) and report an
# entity declaration as a problem instead of expanding it.
# - web-validator-xml-defused: the script never imports the stdlib XML parsers and parses with defusedxml.
# - web-validator-xml-entity-refused: a scratch repository holding validate-site.py and one SVG that declares an
#   entity; the validator must exit 1 and name the SVG as refused. A plain SVG in the same scratch tree is not named.
# The validator runs with the validate job's venv (.ci-venv, where the deps step installed defusedxml) when present.
require 'json'
require 'open3'
require 'tmpdir'
require 'fileutils'

VX_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
VX_SCRIPT = File.join(VX_ROOT, 'scripts', 'validate-site.py')
VX_SOURCE = File.file?(VX_SCRIPT) ? File.read(VX_SCRIPT) : ''
VX_VENV_PY = File.join(VX_ROOT, '.ci-venv', 'bin', 'python')
VX_PYTHON = File.executable?(VX_VENV_PY) ? VX_VENV_PY : 'python3'

VX_ENTITY_SVG = <<~SVG.freeze
  <?xml version="1.0"?>
  <!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&b;</text></svg>
SVG
VX_PLAIN_SVG = %(<svg xmlns="http://www.w3.org/2000/svg"><text>ok</text></svg>\n).freeze

# stigready-web#84: the validator also requires catalog.json (check_catalog), so a scratch tree without one exits 1
# whatever else is in it. The scratch tree carries a catalog.json (one row of the real one, so it follows
# REQUIRED_KEYS), which makes the exit status mean what the control says: 1 only for the SVG's entity, 0 without it.
VX_CATALOG_FILE = File.join(VX_ROOT, 'catalog.json')
VX_CATALOG = JSON.generate('products' => JSON.parse(File.read(VX_CATALOG_FILE)).fetch('products').first(1)).freeze

def vx_run(with_entity)
  Dir.mktmpdir('validator-xml') do |dir|
    FileUtils.mkdir_p(File.join(dir, 'scripts'))
    FileUtils.cp(VX_SCRIPT, File.join(dir, 'scripts')) if File.file?(VX_SCRIPT)
    File.write(File.join(dir, 'entity.svg'), VX_ENTITY_SVG) if with_entity
    File.write(File.join(dir, 'plain.svg'), VX_PLAIN_SVG)
    File.write(File.join(dir, 'catalog.json'), VX_CATALOG)
    File.write(File.join(dir, 'index.html'), "<!doctype html>\n") # the validator reads the home page
    Open3.capture2e('git', '-C', dir, 'init', '-q')
    Open3.capture2e('git', '-C', dir, 'add', '-A')
    out, st = Open3.capture2e(VX_PYTHON, File.join(dir, 'scripts', 'validate-site.py'))
    [out, st.exitstatus]
  end
end

VX_OUT, VX_RC = vx_run(true)
VX_CLEAN_OUT, VX_CLEAN_RC = vx_run(false)

control 'web-validator-xml-defused' do
  impact 1.0
  title 'validate-site.py parses XML/SVG with defusedxml, never the stdlib parsers (stigready-web#57)'
  describe 'scripts/validate-site.py stdlib XML imports' do
    subject { VX_SOURCE.scan(/^\s*(?:import\s+xml\b|from\s+xml\b)[^\n]*/) }
    it { should be_empty }
  end
  describe 'scripts/validate-site.py' do
    subject { VX_SOURCE }
    it { should match(/^import defusedxml\.ElementTree as DET$/) }
    it { should match(/\bDET\.parse\(/) }
  end
end

control 'web-validator-xml-entity-refused' do
  impact 1.0
  title 'validate-site.py reports an SVG that declares an entity, and passes a plain one (stigready-web#57)'
  desc 'validator output on the scratch tree:', VX_OUT
  describe 'validate-site.py exit status on a tree with an entity-bearing SVG' do
    subject { VX_RC }
    it { should eq 1 }
  end
  describe 'its report' do
    subject { VX_OUT }
    it { should match(/entity\.svg: XML declares an entity or external reference, refused/) }
    it { should match(/validate-site: 1 problem\(s\)/) }
    it { should_not match(/plain\.svg/) }
    it { should_not match(/catalog\.json/) }
  end
  describe 'validate-site.py exit status on the same tree without the entity-bearing SVG' do
    subject { VX_CLEAN_RC }
    it { should eq 0 }
  end
end
