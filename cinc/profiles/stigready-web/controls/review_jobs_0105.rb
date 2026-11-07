# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# Decision 0105, as amended by 0116 (approved): review/security, review/marketing and review/qa come from Cairn review
# jobs on every pull request head, so a head the merge train makes with update-branch gets its verdicts back from
# Cairn's own code (a carry-over when the head's tree equals the reviewed head merged with main), not from a person.
# Until the review key is in place the jobs are carry-over only (0105 section 2): their base is the newest
# review/<role> by a base_identities login on an earlier head, and anything that is not a clean carry-over is pending
# "full review needed", never success.
#
# What these controls keep, because each one is a way a review status could turn green without a review, or a way
# this public repository could name a private one:
#   - one job per context, a real review job (Cairn's code decides its status), naming its role (agent_role) and never
#     an agent repository: Cairn's server config maps the role to the pinned agent (decision 0116 part 2), and the
#     pipeline says public: true so Cairn refuses any repository it names;
#   - nothing can skip it: no review.paths, no skip_branches, no if/run_on/needs, pull requests only. A skipped review
#     reports success under the context, and a path filter pinned here could lag the merge train's public-facing list;
#   - the carry-over rests on the right history: require names exactly the contexts branch protection requires here
#     (the validate-history rule), and base_identities is empty: no interim verdict is a base (stigready#5569);
#   - advisory, with a timeout: a needs-review job fails, and must neither turn the aggregate red nor hold it.
require 'yaml'

RJ0105_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
RJ0105_PIPELINE = YAML.safe_load(File.read(File.join(RJ0105_ROOT, '.cairn.yml')))
RJ0105_JOBS = Array(RJ0105_PIPELINE['jobs'])
# The contexts branch protection requires on main here (stigready scripts/merge-train.py POLICY "expect").
RJ0105_REQUIRED = %w[validate].freeze
RJ0105_ROLES = {
  'review/security' => 'security',
  'review/marketing' => 'marketing',
  'review/qa' => 'qa',
}.freeze
# stigready/stigready#5569 (after claude-agents decision 0159): no interim poster is a carry-over base. sclark007 is off
# review_identities, and the reviewer App cannot be a base (Cairn: Apps are never a base), so base_identities is empty.

module ReviewJobs0105
  module_function

  def jobs_for(ctx)
    RJ0105_JOBS.select { |j| j.is_a?(Hash) && j['status'] == ctx }
  end

  def timeout_minutes(t)
    m = t.to_s.match(/\A(\d+)(s|m|h)\z/) or return nil
    { 's' => 1.0 / 60, 'm' => 1, 'h' => 60 }[m[2]] * m[1].to_i
  end
end

control 'review-jobs-0105-01' do
  impact 1.0
  title 'review/security, review/marketing and review/qa each come from exactly one Cairn review job naming its role'
  desc 'Decision 0105 section 1: the verdict and its carry-over come from one job, one context and Cairn\'s app. ' \
       'Decision 0116 part 2: the job names its role, never an agent repository, and the pipeline is public.'
  describe 'the pipeline' do
    subject { RJ0105_PIPELINE }
    its(['public']) { should eq true }
    it { should_not have_key 'include' }
  end
  RJ0105_ROLES.each do |ctx, role|
    jobs = ReviewJobs0105.jobs_for(ctx)
    describe "jobs reporting #{ctx}" do
      subject { jobs.size }
      it { should eq 1 }
    end
    review = (jobs.first || {})['review'] || {}
    describe "#{ctx}: review" do
      subject { review }
      its(['agent_role']) { should eq role }
      it { should_not have_key 'agent' }
    end
    describe "#{ctx}: the job runs nothing of its own" do
      subject { (jobs.first || {}).keys }
      it { should_not include 'run' }
      it { should_not include 'matrix' }
    end
  end
  describe 'other jobs reporting a review/* context' do
    subject { RJ0105_JOBS.select { |j| j.is_a?(Hash) && j['status'].to_s.start_with?('review/') && !j.key?('review') }.map { |j| j['name'] } }
    it { should be_empty }
  end
end

control 'review-jobs-0105-02' do
  impact 1.0
  title 'Nothing can skip a review job on a pull request (a skipped review reports success)'
  desc 'No review.paths, no skip_branches, no if/run_on/needs, and pull requests only: no filter may skip a PR the ' \
       'merge train treats as public-facing.'
  RJ0105_ROLES.each_key do |ctx|
    job = ReviewJobs0105.jobs_for(ctx).first || {}
    review = job['review'] || {}
    describe "#{ctx}: review filters" do
      subject { review.keys }
      it { should_not include 'paths' }
      it { should_not include 'skip_branches' }
    end
    describe "#{ctx}: job conditions" do
      subject { job.keys }
      it { should_not include 'if' }
      it { should_not include 'run_on' }
      it { should_not include 'needs' }
      it { should_not include 'changes' }
    end
    describe "#{ctx}: when" do
      subject { job.fetch('when', 'pull_request') }
      it { should eq 'pull_request' }
    end
  end
end

control 'review-jobs-0105-03' do
  impact 1.0
  title 'Carry-over only rests on Cairn\'s own green reviewed head, never an interim poster, and never holds the aggregate'
  desc 'Decision 0105 sections 1.3 and 2: require is every context branch protection requires; base_identities is ' \
       'empty (stigready#5569: no interim verdict is a carry-over base after 0159; never an App: Cairn reads its own ' \
       'verdicts from its runs); advisory with a timeout.'
  RJ0105_ROLES.each_key do |ctx|
    job = ReviewJobs0105.jobs_for(ctx).first || {}
    review = job['review'] || {}
    describe "#{ctx}: review.require" do
      subject { Array(review['require']).sort }
      it { should eq RJ0105_REQUIRED.sort }
    end
    describe "#{ctx}: review.base_identities" do
      subject { review['base_identities'] }
      it { should eq [] }
    end
    describe "#{ctx}: advisory" do
      subject { job['advisory'] }
      it { should eq true }
    end
    describe "#{ctx}: timeout in minutes" do
      subject { ReviewJobs0105.timeout_minutes(job['timeout']) }
      it { should_not be_nil }
      it { should be <= 15 }
    end
  end
end
