# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
# claude-agents#155: how-to role pins cannot fall behind the role our images were built with, and the sitemap
# dates every URL (decision 0003: CINC asserts).
# - A how-to post that pins a public StigForge role (`src: https://github.com/stigready/<repo>` + `version: vX.Y.Z`)
#   pins a tag no older than every role_version stigforge-factory.json records for that repo's scored images, and
#   its "Role pin used in this post" line names the same tag. The posts pinned v0.3.3 while the images were built
#   with 0.3.35 and 0.3.45.
# - Every sitemap.xml <url> has a <lastmod> that is a real YYYY-MM-DD date, not after today.
require 'date'
require 'json'

BLOG_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
BLOG_POSTS = Dir.chdir(BLOG_ROOT) { IO.popen(%w[git ls-files -z -- blog/*.html], &:read).split("\0").sort }
BLOG_FACTORY = JSON.parse(File.read(File.join(BLOG_ROOT, 'stigforge-factory.json')))
BLOG_SITEMAP = File.read(File.join(BLOG_ROOT, 'sitemap.xml'))

module BlogPins
  module_function

  # repo ("stigready/rhel9-stig") => the role versions its scored images were built with.
  def built_versions(factory)
    factory.fetch('cells', []).each_with_object(Hash.new { |h, k| h[k] = [] }) do |cell, out|
      Array(cell['profiles']).each { |p| out[cell['github_repo']] << p['role_version'] if p['role_version'] }
    end
  end

  # [[repo, "vX.Y.Z"], ...] from each requirements.yml block in a post.
  def pins(body)
    body.scan(%r{src:\s*https://github\.com/(stigready/[\w.-]+)\s*\n\s*scm:\s*git\s*\n\s*version:\s*(v[\d.]+)})
  end

  def stated_pins(body)
    body.scan(%r{Role pin used in this post:\s*<code>(v[\d.]+)</code>}).flatten
  end

  def ver(tag)
    Gem::Version.new(tag.delete_prefix('v'))
  end
end

BLOG_BUILT = BlogPins.built_versions(BLOG_FACTORY)
BLOG_PINNED = BLOG_POSTS.to_h { |rel| [rel, BlogPins.pins(File.read(File.join(BLOG_ROOT, rel)))] }

control 'web-blog-pins-found' do
  impact 1.0
  title 'The pin control sees the how-to posts and the factory role versions'
  describe 'blog posts that pin a role' do
    subject { BLOG_PINNED.reject { |_, v| v.empty? }.keys }
    it { should include 'blog/rhel9-base-stigforge-stig.html' }
    it { should include 'blog/ubuntu24-base-stigforge-cis.html' }
  end
end

control 'web-blog-role-pins-current' do
  impact 1.0
  title 'How-to role pins are no older than the role version our scored images were built with'
  BLOG_PINNED.each do |rel, pins|
    body = File.read(File.join(BLOG_ROOT, rel))
    pins.each do |repo, tag|
      built = BLOG_BUILT[repo]
      describe "#{rel} pins #{repo} #{tag}: role versions in stigforge-factory.json" do
        subject { built }
        it { should_not be_empty }
      end
      next if built.empty?

      oldest_built = built.map { |v| BlogPins.ver(v) }.min
      describe "#{rel} pin #{tag} for #{repo} (images built with #{built.uniq.sort.join(', ')})" do
        subject { BlogPins.ver(tag) >= oldest_built }
        it { should eq true }
      end
    end
    BlogPins.stated_pins(body).each do |stated|
      describe "#{rel} 'Role pin used in this post' #{stated} matches requirements.yml" do
        subject { pins.map(&:last) }
        it { should include stated }
      end
    end
  end
end

control 'web-sitemap-lastmod' do
  impact 1.0
  title 'Every sitemap.xml URL has a valid <lastmod> date, not in the future'
  urls = BLOG_SITEMAP.scan(%r{<url>(.*?)</url>}m).flatten
  describe 'sitemap.xml <url> entries' do
    subject { urls }
    it { should_not be_empty }
  end
  urls.each do |u|
    loc = u[%r{<loc>(.*?)</loc>}, 1]
    lastmod = u[%r{<lastmod>(\d{4}-\d{2}-\d{2})</lastmod>}, 1]
    describe "sitemap #{loc} <lastmod>" do
      subject { lastmod }
      it { should_not be_nil }
    end
    next if lastmod.nil?

    date = begin
      Date.iso8601(lastmod)
    rescue ArgumentError
      nil
    end
    describe "sitemap #{loc} <lastmod> #{lastmod} is a real date, not after today" do
      subject { !date.nil? && date <= Date.today + 1 }
      it { should eq true }
    end
  end
end
