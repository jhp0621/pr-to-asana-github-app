require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'asana'
require 'date'
require 'pry'

set :port, 3000
set :bind, '0.0.0.0'

# This is template code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# On its own, this app does absolutely nothing, except that it can be installed.
# It's up to you to add functionality!
# You can check out one example in advanced_server.rb.
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.
#
# Of course, not all apps need to receive and process events!
# Feel free to rip out the event handling code if you don't need it.
#
# Have fun!
#

class GHAapp < Sinatra::Application
  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  ASANA_ACCESS_TOKEN = ENV['ASANA_PERSONAL_ACCESS_TOKEN']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end

  # Before each request to the `/event_handler` route
  before '/' do
    if request.env['HTTP_X_GITHUB_EVENT']
      get_payload_request(request)
      verify_webhook_signature
      authenticate_app
      # Authenticate the app installation in order to run API operations
      authenticate_installation(@payload)
      authenticate_asana_app
    end
  end

  asana_project_members = []
  code_review_index = ''
  status_field_id = ''
  
  post '/' do
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'pull_request'
      reviewers = []
      pr_link = ''

      if @payload['action'] == 'review_requested' || @payload['action'] == 'edited' || @payload['action'] == 'ready_for_review'
        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']
        reviewers = @payload['pull_request']['requested_reviewers']

        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task

            next unless task

            if asana_project_members.empty?
              project = @asana_client.projects.get_project(project_gid: project_id, options: { fields: ['members'] })
              asana_project_members = project.members.map do |member|
                @asana_client.users.get_user(user_gid: member['gid'], options: { fields: %w[email name] })
              end
            end

            next if @payload['pull_request']['draft'] # skip updating asana task if the PR is in draft

            status_field = task.custom_fields.find { |field| field['name'].downcase.include? 'status' }
            status_field_id = status_field['gid']
            code_review_option = status_field['enum_options'].find do |option|
              option['name'].downcase.include?('code review') || option['name'].downcase.include?('pr review')
            end
            code_review_index = status_field['enum_options'].index code_review_option
            current_status_option = status_field['enum_value']

            # if it's already in code review, skip updating status
            if current_status_option.nil? || (current_status_option['gid'] != code_review_option['gid'])
              @asana_client.tasks.update_task(task_gid: task_id,
                                              custom_fields: { status_field_id => code_review_option['gid'] })
              @asana_client.stories.create_story_for_task(task_gid: task_id, text: "PR created: #{pr_link}")
            end
            # rescue puts "no task found"

            next if reviewers.empty? || asana_project_members.empty?

            reviewers.each do |reviewer|
              login = reviewer['login']
              github_user = @installation_client.user login # retrieve reviewer's github info (namely, name and email)

              # identify the reviewer's asana account via email/name
              asana_user = asana_project_members.find do |member|
                member.email == github_user[:email] || member.name == github_user[:name]
              end

              subtasks = @asana_client.tasks.get_subtasks_for_task(task_gid: task_id)
              code_review_subtask = subtasks.find { |subtask| subtask.name == "Code Review for #{login}" }
              # if there already is a code review subtask for the reviewer, re-open it if closed
              if code_review_subtask
                code_review_task = @asana_client.tasks.get_task(task_gid: code_review_subtask.gid)
                if code_review_task.completed
                  @asana_client.tasks.update_task(task_gid: code_review_subtask.gid, completed: false)
                end
                # create a subtask for code review if there isn't one
              elsif asana_user

                @asana_client.tasks.create_subtask_for_task(task_gid: task_id, name: "Code Review for #{login}",
                                                            assignee: asana_user.gid,
                                                            due_on: (Date.today + 3).to_s, notes: 'PR',
                                                            html_notes: "<body><a href='#{pr_link}'>PR</a></body>")
              else
                @asana_client.tasks.create_subtask_for_task(task_gid: task_id, name: "Code Review for #{login}",
                                                            due_on: (Date.today + 3).to_s, notes: "PR assigned to #{login}",
                                                            html_notes: "<body><a href='#{pr_link}'>PR</a> assigned to <a href='#{reviewer['html_url']}'>#{login}</a></body>")
              end
            end
          end

        end

      end

      if @payload['action'] == 'review_request_removed'
        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']
        login = @payload['requested_reviewer']['login']

        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task
            next unless task

            subtasks = @asana_client.tasks.get_subtasks_for_task(task_gid: task_id)
            code_review_task = subtasks.find { |subtask| subtask.name == "Code Review for #{login}" }
            @asana_client.tasks.delete_task(task_gid: code_review_task.gid) if code_review_task
          end

        end
      end

      if @payload['action'] == 'closed' && (@payload['pull_request']['merged'])
        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']
        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task
            next unless task

            @asana_client.tasks.update_task(task_gid: task_id,
                                            # update the status to the one that succeeds code review
                                            custom_fields: { status_field_id => status_field['enum_options'][code_review_index + 1]['gid'] })
          end

        end
      end

      if @payload['action'] == 'assigned'
        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']
        login = @payload['assignee']['login']
        github_user = @installation_client.user login

        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task
            next unless task

            if asana_project_members.empty?
              project = @asana_client.projects.get_project(project_gid: project_id,
                                                           options: { fields: ['members'] })
              asana_project_members = project.members.map do |member|
                @asana_client.users.get_user(user_gid: member['gid'], options: { fields: %w[email name] })
              end
            end

            next if @payload['pull_request']['draft'] # skip updating asana task if the PR is in draft

            # identify the assginee's asana account via email/name
            asana_user = asana_project_members.find do |member|
              member.email == github_user[:email] || member.name == github_user[:name]
            end

            subtasks = @asana_client.tasks.get_subtasks_for_task(task_gid: task_id)
            assigned_subtask = subtasks.find { |subtask| subtask.name == "Assigned to #{login}" }

            if assigned_subtask
              assigned_task = @asana_client.tasks.get_task(task_gid: assigned_subtask.gid)
              @asana_client.tasks.update_task(task_gid: assigned_task.gid, completed: false) if assigned_task.completed
            elsif asana_user
              @asana_client.tasks.create_subtask_for_task(task_gid: task_id, name: "Assigned to #{login}",
                                                          assignee: asana_user.gid,
                                                          due_on: (Date.today + 3).to_s, notes: 'PR',
                                                          html_notes: "<body><a href='#{pr_link}'>PR</a></body>")
            else
              @asana_client.tasks.create_subtask_for_task(task_gid: task_id, name: "Assigned to #{login}",
                                                          due_on: (Date.today + 3).to_s, notes: "PR assigned to #{login}",
                                                          html_notes: "<body><a href='#{pr_link}'>PR</a> assigned to <a href='#{@payload['assignee']['html_url']}'>#{login}</a></body>")
            end
          end

        end
      end

      if @payload['action'] == 'unassigned' # when an assignee is removed, we can assume their work (e.g., QA or styling) is done and mark the subtask completed
        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']
        login = @payload['assignee']['login']
        github_user = @installation_client.user login

        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task
            next unless task

            if asana_project_members.empty?
              project = @asana_client.projects.get_project(project_gid: project_id,
                                                           options: { fields: ['members'] })
              asana_project_members = project.members.map do |member|
                @asana_client.users.get_user(user_gid: member['gid'], options: { fields: %w[email name] })
              end
            end

            # identify the assginee's asana account via email/name
            asana_user = asana_project_members.find do |member|
              member.email == github_user[:email] || member.name == github_user[:name]
            end

            subtasks = @asana_client.tasks.get_subtasks_for_task(task_gid: task_id)
            assigned_subtask = subtasks.find { |subtask| subtask.name == "Assigned to #{login}" }
            @asana_client.tasks.update_task(task_gid: assigned_subtask.gid, completed: true) if assigned_subtask
          end

        end
      end

    when 'pull_request_review'
      if @payload['action'] == 'submitted'
        state = @payload['review']['state']
        login = @payload['review']['user']['login']
        github_reviewer = @installation_client.user login

        pr_link = @payload['pull_request']['html_url']
        body_content = @payload['pull_request']['body']

        unless body_content.nil?
          task_links = body_content.split.select { |word| word.include?('app.asana.com') }
          task_links.each do |link|
            # asana url construction: https://app.asana.com/0/{projectId}/{taskId}
            zero_index = link.split('/').index('0')
            project_id = link.split('/')[zero_index + 1]
            task_id = link.split('/')[zero_index + 2]
            task = @asana_client.tasks.get_task(task_gid: task_id) # identify asana task
            next unless task

            if asana_project_members.empty?
              project = @asana_client.projects.get_project(project_gid: project_id,
                                                           options: { fields: ['members'] })
              asana_project_members = project.members.map do |member|
                @asana_client.users.get_user(user_gid: member['gid'], options: { fields: %w[email name] })
              end
            end

            asana_user = asana_project_members.find do |member|
              member.email == github_reviewer[:email] || member.name == github_reviewer[:name]
            end

            if asana_user
              if state == 'changes_requested'
                @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                            html_text: "<body>[Code Review] Changes requested by <a data-asana-type='user' data-asana-gid='#{asana_user.gid}'>#{asana_user.name}</a></body>")

              elsif state == 'commented'
                @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                            html_text: "<body>[Code Review] Comments provided by <a data-asana-type='user' data-asana-gid='#{asana_user.gid}'>#{asana_user.name}</a></body>")

              elsif state == 'approved'
                @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                            html_text: "<body>[Code Review] PR approved by <a data-asana-type='user' data-asana-gid='#{asana_user.gid}'>#{asana_user.name}</a></body>")

              end
            elsif state == 'changes_requested'
              @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                          text: "[Code Review] Changes requested by #{login}")
            elsif state == 'commented'
              @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                          text: "[Code Review] Comments provided by #{login}")
            elsif state == 'approved'
              @asana_client.stories.create_story_for_task(task_gid: task_id,
                                                          text: "[Code Review] PR approved by #{login}")
            end

            subtasks = @asana_client.tasks.get_subtasks_for_task(task_gid: task_id)
            code_review_subtask = subtasks.find { |subtask| subtask.name == "Code Review for #{login}" }
            @asana_client.tasks.update_task(task_gid: code_review_subtask.gid, completed: true) if code_review_subtask
          end

        end

      end

    end

    200 # success status
  end

  helpers do
    # # # # # # # # # # # # # # # # #
    # ADD YOUR HELPER METHODS HERE  #
    # # # # # # # # # # # # # # # # #

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue StandardError => e
        raise "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app and wasn't alterered by
    # a malicious third party.
    def authenticate_app
      payload = {
        # The time that this JWT was issued, _i.e._ now.
        iat: Time.now.to_i,

        # JWT expiration time (10 minute maximum)
        exp: Time.now.to_i + (10 * 60),

        # Your GitHub App's identifier number
        iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

    def authenticate_asana_app
      @asana_client = Asana::Client.new do |c|
        c.authentication :access_token, ASANA_ACCESS_TOKEN
      end
    end
  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
