# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready#5177: Amazon Linux 2023 is built from Amazon's prebuilt disk image (stigready registry/images.yml
# disk_image: true), and its build creates only a separate /var/log/audit (AZLX-23-002020, the one separate partition
# the AL2023 STIG requires). The site said the six-mount ISO layout was "identical across all OS families" and that
# every image is built from the official OS ISO. A paragraph that makes a catalog-wide claim about the ISO, the
# install-time layout or the separate mounts must carry the Amazon Linux 2023 exception, and no page may say the
# layout is identical across OS families.

DL_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
DL_PAGES = Dir.chdir(DL_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }

module DiskLayoutClaims
  module_function

  # The visible text of each <p>, <li>, <td> and <h1>-<h6> block, tags and entities collapsed.
  def blocks(html)
    body = html.gsub(%r{<(script|style)\b.*?</\1>}im, ' ')
    body.scan(%r{<(p|li|td|h[1-6])\b[^>]*>(.*?)</\1>}im).map do |_tag, inner|
      inner.gsub(/<[^>]+>/, ' ').gsub('&nbsp;', ' ').gsub('&amp;', '&').gsub(/&[a-z#0-9]+;/i, ' ').gsub(/\s+/, ' ').strip
    end
  end

  UNIVERSAL = /\b(every|all|identical|same)\b/i
  ISO = /official (OS )?ISO/i
  LAYOUT = %r{/home\b|/var/tmp\b|install-time|separate STIG|STIG filesystems}i
  EXCEPTION = /Amazon Linux 2023/

  def violations(rel, html)
    blocks(html).filter_map do |t|
      next "#{rel}: #{t[0, 160]}" if t =~ /identical across (all )?OS families/i
      next if t =~ EXCEPTION
      next "#{rel}: #{t[0, 160]}" if t =~ ISO || (t =~ UNIVERSAL && t =~ LAYOUT)
    end
  end
end

control 'web-disk-layout-claims-01' do
  impact 1.0
  title 'No page claims the ISO disk layout for every image without the Amazon Linux 2023 exception (stigready#5177)'
  desc 'A paragraph, list item, table cell or heading that says the image is built from the official (OS) ISO, or says
        every/all/identical/same together with the install-time layout or the separate mounts, must name the Amazon
        Linux 2023 exception in the same block.'

  bad = DL_PAGES.flat_map { |rel| DiskLayoutClaims.violations(rel, File.read(File.join(DL_ROOT, rel))) }
  describe 'catalog-wide disk layout claims on the published pages' do
    it('cover at least the home page and the blog') { expect(DL_PAGES).to include('index.html', 'blog/stig-disk-layout-that-wont-fight-you.html') }
    it('all carry the Amazon Linux 2023 exception') { expect(bad).to eq([]), bad.join("\n") }
  end

  home = DiskLayoutClaims.blocks(File.read(File.join(DL_ROOT, 'index.html'))).join("\n")
  describe 'the home page' do
    it('says Amazon Linux 2023 gets a separate /var/log/audit') { expect(home).to match(%r{Amazon Linux 2023[^\n]*/var/log/audit}) }
  end
end
