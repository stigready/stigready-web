# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
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
# Mirrors css_stamp.py SCRIPT_ELEMENT, SCRIPT_SKIP, SCRIPT_SPLIT (stigready-web#67: classes set in JS strings).
CSS_SCRIPT_ELEMENT = %r{<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</script\s*>}im
CSS_SCRIPT_SKIP = %r{\bsrc\s*=|\btype\s*=\s*["']?application/(?:ld\+)?json}i
CSS_SCRIPT_SPLIT = /[ \t\n\r\f\v'"`]+/

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
      text.scan(CSS_SCRIPT_ELEMENT) do |attrs, script|
        script.split(CSS_SCRIPT_SPLIT).each { |t| tokens[t] = true unless t.empty? } unless attrs.match?(CSS_SCRIPT_SKIP)
      end
    end
  end
  tokens.keys.sort
end

def css_stamp_now
  build = File.join(CSS_ROOT, 'scripts', 'build-css.sh')
  version = File.file?(build) ? File.read(build)[/^TAILWIND_VERSION=(\d+\.\d+\.\d+)$/, 1].to_s : ''
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

# stigready-web#67 (review/security on #62): the Tailwind build pinned only the top-level npm package, so npx resolved
# its transitive dependencies afresh on every build. build-css.sh now runs the upstream standalone CLI, one file per
# platform, and checks its sha256 before running it.
CSS_BUILD_TEXT = begin
  File.read(File.join(CSS_ROOT, 'scripts', 'build-css.sh'))
rescue Errno::ENOENT
  ''
end
CSS_BUILD_CODE = CSS_BUILD_TEXT.lines.reject { |l| l.lstrip.start_with?('#') }.join

control 'web-css-build-pinned' do
  impact 1.0
  title 'scripts/build-css.sh runs a sha256-checked Tailwind standalone CLI, never npm (stigready-web#67)'
  describe 'build-css.sh package-manager commands (npx, npm, yarn, pnpm)' do
    subject { CSS_BUILD_CODE.scan(/\b(?:npx|npm|yarn|pnpm)\b/) }
    it { should be_empty }
  end
  %w[linux-x64 linux-arm64 macos-arm64 macos-x64].each do |plat|
    describe "build-css.sh sha256 for tailwindcss-#{plat}" do
      subject { CSS_BUILD_CODE[/\bplat=#{plat} want=([0-9a-f]{64})\b/, 1] }
      it { should_not be_nil }
    end
  end
  describe 'build-css.sh refuses a CLI whose sha256 differs' do
    subject { CSS_BUILD_CODE }
    it { should match(/if \[ "\$got" != "\$want" \]; then\n\s+rm -f "\$tmp"/) }
    it { should match(/^TAILWIND_VERSION=\d+\.\d+\.\d+$/) }
  end
end
