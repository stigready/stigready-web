# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready-web#76: the site runs Google Analytics, so it has a privacy policy and terms of use, every page's footer
# links both, and the sitemap lists both. A redirect stub (meta refresh) has no footer and is the only exception.

LEGAL_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
LEGAL_PAGES = Dir.chdir(LEGAL_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }
LEGAL_BODIES = LEGAL_PAGES.to_h { |rel| [rel, File.binread(File.join(LEGAL_ROOT, rel)).force_encoding('UTF-8').scrub('')] }
LEGAL_LINKS = %w[/privacy/ /terms/].freeze

module LegalPages
  module_function

  def redirect?(body)
    body.match?(/<meta\s+http-equiv="refresh"/i)
  end

  # The pages whose <footer> lacks a link to path (a page with no footer at all counts as missing it).
  def missing(bodies, path)
    bodies.reject { |_, body| redirect?(body) }
          .reject { |_, body| (f = body[%r{<footer\b.*?</footer>}m]) && f.include?(%(href="#{path}")) }.keys
  end
end

control 'web-legal-pages' do
  impact 1.0
  title 'The privacy policy and terms exist, every page footer links both, and the sitemap lists both'
  describe 'tracked pages' do
    subject { LEGAL_PAGES }
    it { should include 'privacy/index.html', 'terms/index.html', 'index.html' }
  end
  LEGAL_LINKS.each do |path|
    describe "pages whose footer does not link #{path}" do
      subject { LegalPages.missing(LEGAL_BODIES, path) }
      it { should eq [] }
    end
    describe "sitemap.xml lists https://stigready.com#{path}" do
      subject { File.read(File.join(LEGAL_ROOT, 'sitemap.xml')) }
      it { should include "<loc>https://stigready.com#{path}</loc>" }
    end
  end
end

control 'web-legal-pages-guard-fails' do
  impact 1.0
  title 'The footer-link check fails on a page without the links'
  describe 'made-up pages' do
    bad = { 'a.html' => '<footer><a href="/terms/">T</a></footer>', 'b.html' => '<p><a href="/privacy/">P</a></p>',
            'c.html' => '<meta http-equiv="refresh" content="0">', 'd.html' => '<footer><a href="/privacy/">P</a></footer>' }
    it('flag a footer without the link and a page without a footer') do
      expect(LegalPages.missing(bad, '/privacy/')).to eq(%w[a.html b.html])
    end
  end
end
