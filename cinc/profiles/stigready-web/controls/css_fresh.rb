# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
# claude-agents#152: assets/css/site.css is what scripts/build-css.sh wrote for the current pages, config and Tailwind
# version. The runners cannot run Tailwind, so build-css.sh records a stamp (scripts/css_stamp.py --write, building)
# and this control recomputes every field exactly as css_stamp.py defines it and compares (decision 0003: the
# assertion is CINC's). Ported from validate-site.py check 9.
require 'digest'
require 'json'

CSS_ROOT   = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
CSS_FILE   = File.join(CSS_ROOT, 'assets', 'css', 'site.css')
CSS_STAMP  = File.join(CSS_ROOT, 'assets', 'css', 'site.css.stamp.json')
# Mirrors css_stamp.py: PAGE_GLOBS (tailwind.config.js `content`), CLASS_ATTR, CLASS_LIST.
CSS_PAGE_GLOBS = ['*.html', 'applied/*.html', 'blog/*.html'].freeze
CSS_CLASS_ATTR = /\bclass\s*=\s*(?:"([^"]*)"|'([^']*)')/
CSS_CLASS_LIST = /classList\.(?:add|remove|toggle)\(\s*(['"])([^'"]+)\1/

def css_sha(path)
  File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil
end

def css_class_tokens
  tokens = {}
  CSS_PAGE_GLOBS.each do |glob|
    Dir.glob(File.join(CSS_ROOT, glob)).sort.each do |page|
      text = File.binread(page).force_encoding('UTF-8').scrub('')
      text.scan(CSS_CLASS_ATTR) { |dq, sq| (dq.nil? ? sq : dq).split.each { |t| tokens[t] = true } }
      text.scan(CSS_CLASS_LIST) { |_q, list| list.split.each { |t| tokens[t] = true } }
    end
  end
  tokens.keys.sort
end

def css_stamp_now
  build = File.join(CSS_ROOT, 'scripts', 'build-css.sh')
  version = File.file?(build) ? File.read(build)[/tailwindcss@(\d+\.\d+\.\d+)/, 1].to_s : ''
  {
    'tailwindcss' => version,
    'config_sha256' => css_sha(File.join(CSS_ROOT, 'tailwind.config.js')),
    'input_sha256' => css_sha(File.join(CSS_ROOT, 'assets', 'css', 'tailwind.input.css')),
    'class_tokens_sha256' => Digest::SHA256.hexdigest(css_class_tokens.join("\n")),
    'site_css_sha256' => css_sha(CSS_FILE),
  }
end

CSS_STAMP_WANT = begin
  File.file?(CSS_STAMP) ? JSON.parse(File.read(CSS_STAMP)) : {}
rescue JSON::ParserError
  {}
end
CSS_STAMP_GOT = css_stamp_now

CSS_STAMP_WHY = {
  'tailwindcss' => 'the Tailwind CLI version in scripts/build-css.sh changed',
  'config_sha256' => 'tailwind.config.js changed',
  'input_sha256' => 'assets/css/tailwind.input.css changed',
  'class_tokens_sha256' => 'the classes on the pages changed',
  'site_css_sha256' => 'assets/css/site.css is not the file scripts/build-css.sh wrote',
}.freeze

control 'web-site-css-fresh' do
  impact 1.0
  title 'assets/css/site.css matches its build stamp (run scripts/build-css.sh and commit both files)'
  describe file(CSS_STAMP) do
    it { should be_file }
  end
  describe 'site.css.stamp.json parses as a JSON object with every field' do
    subject { CSS_STAMP_WANT.keys }
    it { should include(*CSS_STAMP_WHY.keys) }
  end
  CSS_STAMP_WHY.each do |key, why|
    describe "site.css stamp #{key} (stale if #{why})" do
      subject { CSS_STAMP_GOT[key] }
      it { should_not be_nil }
      it { should eq CSS_STAMP_WANT[key] }
    end
  end
end
