# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready-web#77: GitHub Pages publishes main with Jekyll, and only the site's own files may reach stigready.com.
# The pipeline config, the CINC profile, the build scripts and the repository's papers stay in the repo.
#
# These controls work out what Jekyll would publish from the checked-out tree, using the rules GitHub Pages applies:
# every tracked file, minus any path with a component that starts with "." or "_", minus every _config.yml `exclude`
# entry (a path, a path prefix, or a glob). Then:
# - every published path must be a site path (SITE_PATHS); a new top-level file or directory fails here until it is
#   either part of the site or excluded in _config.yml;
# - .nojekyll must not exist (with it, Pages skips Jekyll and serves the whole tree, excludes and all);
# - no published file may be one Jekyll would transform rather than copy (front matter, Markdown, Sass), so the live
#   site is the checked-in bytes;
# - no published text file may name a private repository, a private issue or an internal design decision (the
#   markers stigforge's public_scrub.find_internal_refs uses for the public role repos).
# The -guard-fails control runs the same checks on made-up trees and proves each one fails.
require 'yaml'

PUB_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

module PublishedPaths
  module_function

  # The site: pages, their assets and the data files the pages fetch. Globs use File.fnmatch with FNM_PATHNAME.
  SITE_PATHS = %w[
    CNAME robots.txt sitemap.xml index.html stigapplied.html catalog.json stigforge-factory.json
    applied/*.html blog/*.html blog/rss.xml
    privacy/*.html terms/*.html
    assets/*.png assets/*.svg assets/css/site.css assets/vendor/*
  ].freeze

  # Extensions Jekyll converts instead of copying.
  CONVERTED = %w[.md .markdown .mkd .mkdn .mdown .textile .scss .sass .coffee].freeze

  # The private repos and markers from stigforge generator/public_scrub.py (stigready-web is public on purpose).
  PRIVATE_REPOS = %w[stigforge claude-agents stigready stigvalidated cairn build-reports cmmc-agents-field-manual].freeze
  INTERNAL_MARKERS = [
    %r{stigready/(?:#{PRIVATE_REPOS.map { |r| Regexp.escape(r) }.join('|')})(?![\w-])|stigready/stigvalidated-[\w-]+},
    /\b(?:stigforge|stigready|stigvalidated|claude-agents|cairn)#\d+\b/,
    /\b[Dd]ecision\s+0\d{3}\b/,
    /\b[Oo]wner(?:\s+decision|\s+direction|,\s*20\d\d-\d\d-\d\d)/,
    /\bdesign backlog\b|\bcoverage-backlog\b/i,
  ].freeze
  TEXT_EXT = %w[.html .xml .json .txt .js .css .svg].freeze

  # Jekyll 3's EntryFilter#glob_include?: a String pattern matches by fnmatch or as a path prefix.
  def excluded?(path, excludes)
    excludes.any? { |pat| File.fnmatch?(pat, path) || path.start_with?(pat) }
  end

  def hidden?(path)
    path.split('/').any? { |part| part.start_with?('.', '_') }
  end

  def published(files, excludes)
    files.reject { |f| hidden?(f) || excluded?(f, excludes) }.sort
  end

  def non_site(paths)
    paths.reject { |p| SITE_PATHS.any? { |g| File.fnmatch?(g, p, File::FNM_PATHNAME) } }
  end

  # name => content for files Jekyll would transform.
  def transformed(contents)
    contents.select { |name, body| CONVERTED.include?(File.extname(name).downcase) || body.start_with?("---\n", "---\r\n") }.keys
  end

  def internal_refs(contents)
    contents.flat_map do |name, body|
      next [] unless TEXT_EXT.include?(File.extname(name).downcase)

      body.each_line.with_index(1).flat_map do |line, n|
        INTERNAL_MARKERS.filter_map { |m| (hit = line[m]) && "#{name}:#{n}: #{hit}" }
      end
    end
  end
end

PUB_FILES = Dir.chdir(PUB_ROOT) { IO.popen(%w[git ls-files -z], &:read).split("\0") }
PUB_CONFIG = YAML.safe_load(File.read(File.join(PUB_ROOT, '_config.yml'))) || {}
PUB_EXCLUDES = Array(PUB_CONFIG['exclude']).map(&:to_s)
PUB_PATHS = PublishedPaths.published(PUB_FILES, PUB_EXCLUDES)
PUB_CONTENTS = PUB_PATHS.to_h { |p| [p, File.binread(File.join(PUB_ROOT, p)).force_encoding('UTF-8').scrub] }

control 'web-published-paths-site-only' do
  impact 1.0
  title 'stigready.com publishes only the site: no CI, test, script or repository files (stigready-web#77)'
  desc 'GitHub Pages builds main with Jekyll; _config.yml excludes everything that is not a site path.'
  describe 'the files Pages would publish' do
    it('include the home page') { expect(PUB_PATHS).to include('index.html') }
    it('include no file outside the site paths') { expect(PublishedPaths.non_site(PUB_PATHS)).to eq([]) }
    it('include no CI or test file') { expect(PUB_PATHS.grep(%r{\A(\.cairn\.yml|cinc/|scripts/)})).to eq([]) }
  end
  describe 'the Pages build' do
    it('runs Jekyll (no .nojekyll, which would serve the whole tree)') { expect(PUB_FILES).not_to include('.nojekyll') }
    it('copies every published file as is (no front matter, Markdown or Sass)') do
      expect(PublishedPaths.transformed(PUB_CONTENTS)).to eq([])
    end
  end
  describe 'published text' do
    it('names no private repo, private issue or internal decision') do
      expect(PublishedPaths.internal_refs(PUB_CONTENTS)).to eq([])
    end
  end
end

control 'web-published-paths-guard-fails' do
  impact 1.0
  title 'The published-paths checks fail on a tree that would leak'
  desc 'Each check above, run on made-up inputs it must reject.'
  describe 'web-published-paths-site-only on bad trees' do
    files = %w[index.html .cairn.yml _config.yml README.md cinc/x/inspec.yml scripts/a.py approvals/README.md
               assets/css/tailwind.input.css blog/a.html]
    excludes = %w[README.md cinc scripts assets/css/tailwind.input.css]
    pub = PublishedPaths.published(files, excludes)
    it('drop dotfiles, _ files and excludes') { expect(pub).to eq(%w[approvals/README.md blog/a.html index.html]) }
    it('flag a new directory that is not excluded') { expect(PublishedPaths.non_site(pub)).to eq(['approvals/README.md']) }
    it('flag everything when nothing is excluded') do
      expect(PublishedPaths.non_site(PublishedPaths.published(files, []))).to include('cinc/x/inspec.yml', 'scripts/a.py')
    end
    it('flag front matter and Markdown') do
      expect(PublishedPaths.transformed('a.html' => "---\ntitle: x\n---\n", 'b.md' => 'x', 'c.html' => '<p>')).to eq(%w[a.html b.md])
    end
    it('flag internal references') do
      bad = { 'a.html' => "<!-- decision 0062 -->\n", 'b.js' => "// see claude-agents#154\n",
              'c.html' => "stigready/stigforge\n", 'd.html' => "stigready/stigready-web#77 is public\n" }
      expect(PublishedPaths.internal_refs(bad).map { |r| r.split(':').first }).to eq(%w[a.html b.js c.html])
    end
  end
end
