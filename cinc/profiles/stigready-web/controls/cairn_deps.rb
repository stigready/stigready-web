# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
# stigready-web#67 (review/security on #64): the validate job's deps step installs only hash-pinned wheels, and its
# mirror list cannot split or glob-expand. Every `pip install` line passes --require-hashes and --only-binary :all:
# (the sdist hash in scripts/requirements-validate.txt must never let pip build from source), and $MIRROR_DIR appears
# only inside double quotes (an unquoted ${MIRROR_DIR:-} in the `for` list splits on spaces and expands globs).
require 'yaml'

DEPS_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
DEPS_PIPELINE = YAML.safe_load(File.read(File.join(DEPS_ROOT, '.cairn.yml')))

module CairnDeps
  module_function

  def step(pipeline, job_name, step_name)
    job = Array(pipeline['jobs']).find { |j| j['name'] == job_name } || {}
    steps = job.dig('run', 'exec', 'steps') || []
    steps.find { |s| s['name'] == step_name } || {}
  end

  def pip_installs(script)
    script.to_s.lines.map(&:strip).select { |l| l.match?(/\bpip\s+install\b/) }
  end

  # Each $MIRROR_DIR / ${MIRROR_DIR...} reference outside a double-quoted string, line by line (the step quotes on
  # one line). Single quotes would not expand it at all, so they count as outside too.
  def unquoted_mirror_refs(script)
    script.to_s.lines.flat_map do |line|
      outside = line.gsub(/"(?:[^"\\]|\\.)*"/, '""')
      outside.scan(/\$\{?MIRROR_DIR\b[^}\s]*\}?/)
    end
  end
end

DEPS_SCRIPT = CairnDeps.step(DEPS_PIPELINE, 'validate', 'deps')['run'].to_s
DEPS_PIPS = CairnDeps.pip_installs(DEPS_SCRIPT)

control 'web-deps-step-found' do
  impact 1.0
  title 'The deps-step controls see the validate job deps step and its pip installs'
  desc 'A control over an empty step asserts nothing.'
  describe 'validate/deps pip install lines' do
    subject { DEPS_PIPS }
    it { should_not be_empty }
  end
end

control 'web-deps-wheels-only-hash-checked' do
  impact 1.0
  title 'Every pip install in the deps step is --require-hashes and --only-binary :all:'
  DEPS_PIPS.each do |line|
    describe "deps: #{line}" do
      subject { line }
      it { should match(/(^|\s)--require-hashes(\s|$)/) }
      it { should match(/(^|\s)--only-binary(\s+|=):all:(\s|$)/) }
    end
  end
end

control 'web-deps-mirror-dir-quoted' do
  impact 1.0
  title 'The deps step uses $MIRROR_DIR only inside double quotes'
  describe 'validate/deps unquoted MIRROR_DIR references' do
    subject { CairnDeps.unquoted_mirror_refs(DEPS_SCRIPT) }
    it { should be_empty }
  end
end
