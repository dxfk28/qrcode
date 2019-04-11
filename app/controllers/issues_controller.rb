# Redmine - project management software
# Copyright (C) 2006-2017  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# require 'aes'
class IssuesController < ApplicationController
  default_search_scope :issues

  before_action :find_issue, :only => [:show, :edit, :update]
  before_action :find_issues, :only => [:bulk_edit, :bulk_update, :destroy]
  before_action :authorize, :except => [:index, :new, :create,:create_data]
  before_action :find_optional_project, :only => [:index, :new, :create]
  before_action :build_new_issue_from_params, :only => [:new, :create]
  accept_rss_auth :index, :show
  accept_api_auth :index, :show, :create, :update, :destroy, :create_data

  rescue_from Query::StatementInvalid, :with => :query_statement_invalid

  helper :journals
  helper :projects
  helper :custom_fields
  helper :issue_relations
  helper :watchers
  helper :attachments
  helper :queries
  include QueriesHelper
  helper :repositories
  helper :timelog

  def decrypt(encrypted)
    dec = OpenSSL::Cipher.new('aes-128-ecb')
    dec.key = 'KaNdKgMjN5l8D5JT'
    dec.decrypt
    plain_text = ""
    plain_text << dec.update(Base64.decode64(encrypted))
    plain_text << dec.final
    return plain_text
  end

  def create_data
    content = decrypt(params[:msg])
    result = JSON.parse content
    is_true = true
    message = ''
    user = User.find_by(login:result['username'])
    if user.blank?
      is_true = false
      message = '用户不存在'
      return render json: {"result" => is_true, 'message' => message}
    end
    issue_info = Issue.find_by(project_id:2,tracker_id:5,subject:result['SN'])
    if issue_info.blank?
      is_true = false
      message = '该SN号没有对应设备信息'
      return render json: {"result" => is_true, 'message' => message}
    end
    Issue.transaction do
      issue = Issue.new(project_id:1,tracker_id:4)
      issue.subject = '--'
      issue.status_id = 1
      issue.priority_id = 1
      issue.author_id = user.id
      unless issue.save
        is_true = false
        message = 'issue数据创建失败'
        raise ActiveRecord::Rollback
      end
      cf1 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:9)
      cf1.value = result['NAME']
      cf2 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:16)
      cf2.value = result['SN']
      cf3 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:62)
      cf3.value = result['Time']
      cf4 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:60)
      cf4.value = result['CTT'].to_i + result['PTT'].to_i + result['STS'].to_i
      cf5 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:61)
      cf5.value = result['PTT'].to_i
      cf6 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:63)
      cf6.value = cf4.value
      cf7 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:67)
      cf7.value = result['CTT']
      cf8 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:68)
      cf8.value = result['CTB']
      cf9 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:69)
      cf9.value = result['CTF']
      cf10 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:71)
      cf10.value = result['CTS']
      cf11 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:72)
      cf11.value = result['CTD']
      cf12 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:73)
      cf12.value = result['CLT']
      cf13 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:74)
      cf13.value = result['CLB']
      cf14 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:75)
      cf14.value = result['CLF']
      cf15 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:76)
      cf15.value = result['CLS']
      cf16 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:77)
      cf16.value = result['CLD']
      cf17 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:78)
      cf17.value = result['PTT']
      cf18 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:79)
      cf18.value = result['PTB']
      cf19 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:80)
      cf19.value = result['PTF']
      cf20 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:81)
      cf20.value = result['PTD']
      cf21 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:82)
      cf21.value = result['PLT']
      cf22 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:83)
      cf22.value = result['PLB']
      cf23 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:84)
      cf23.value = result['PLF']
      cf24 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:85)
      cf24.value = result['PLD']
      cf25 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:88)
      cf25.value = result['STS']
      cf26 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:89)
      cf26.value = result['SLS']
      cf27 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:92)
      cf27.value = result['CTF'].to_i + result['PTF'].to_i + result['STF'].to_i
      cf28 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:93)
      cf28.value = result['CTB'].to_i + result['PTB'].to_i + result['STB'].to_i
      cf29 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:94)
      cf29.value = result['CTD'].to_i + result['PTD'].to_i
      cf30 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:98)
      cf30.value = result['SLF']
      cf31 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:7)
      cf31.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:7).value
      cf32 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:8)
      cf32.value = result['SN']
      cf33 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:10)
      cf33.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:10).value
      cf34 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:11)
      cf34.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:11).value
      cf35 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:59)
      cf35.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:59).value
      cf36 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:14)
      cf36.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:14).value
      cf37 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:15)
      cf37.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:15).value
      cf38 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:18)
      cf38.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:18).value
      cf39 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:19)
      cf39.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:19).value 
      cf40 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:99)
      cf40.value = CustomValue.find_by(customized_type:"Issue",customized_id:issue_info.id,custom_field_id:99).value
      cf41 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:95)
      cf41.value = result['STB']
      cf42 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:96)
      cf42.value = result['SLB']
      cf43 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:97)
      cf43.value = result['STF']
      cf44 = CustomValue.find_by(customized_type:"Issue",customized_id:issue.id,custom_field_id:98)
      cf44.value = result['SLF']
      unless cf1.save && cf2.save && cf3.save && cf4.save && cf5.save && cf6.save && cf7.save && cf8.save && cf9.save && cf10.save && cf11.save && cf12.save && cf13.save && cf14.save && cf15.save && cf16.save && cf17.save && cf18.save && cf19.save && cf20.save && cf21.save && cf22.save && cf23.save && cf24.save && cf25.save && cf26.save && cf27.save && cf28.save && cf29.save && cf30.save && cf31.save&& cf32.save&& cf33.save&& cf34.save&& cf35.save&& cf36.save&& cf37.save&& cf38.save&& cf39.save&&cf40.save&&cf41.save&&cf42.save&&cf43.save&&cf44.save
        is_true = false
        message = '自定义属性创建失败'
        raise ActiveRecord::Rollback
      end
    end
    return render json: {"result" => is_true, 'message' => message}
  end

  def index
    use_session = !request.format.csv?
    retrieve_query(IssueQuery, use_session)

    if @query.valid?
      respond_to do |format|
        format.html {
          @issue_count = @query.issue_count
          @issue_pages = Paginator.new @issue_count, per_page_option, params['page']
          @issues = @query.issues(:offset => @issue_pages.offset, :limit => @issue_pages.per_page)
          render :layout => !request.xhr?
        }
        format.api  {
          @offset, @limit = api_offset_and_limit
          @query.column_names = %w(author)
          @issue_count = @query.issue_count
          @issues = @query.issues(:offset => @offset, :limit => @limit)
          Issue.load_visible_relations(@issues) if include_in_api_response?('relations')
        }
        format.atom {
          @issues = @query.issues(:limit => Setting.feeds_limit.to_i)
          render_feed(@issues, :title => "#{@project || Setting.app_title}: #{l(:label_issue_plural)}")
        }
        format.csv  {
          @issues = @query.issues(:limit => Setting.issues_export_limit.to_i)
          Issue.download_count(@issues)
          send_data(query_to_csv(@issues, @query, params[:csv]), :type => 'text/csv; header=present', :filename => 'issues.csv')
        }
        format.pdf  {
          @issues = @query.issues(:limit => Setting.issues_export_limit.to_i)
          send_file_headers! :type => 'application/pdf', :filename => 'issues.pdf'
        }
      end
    else
      respond_to do |format|
        format.html { render :layout => !request.xhr? }
        format.any(:atom, :csv, :pdf) { head 422 }
        format.api { render_validation_errors(@query) }
      end
    end
  rescue ActiveRecord::RecordNotFound
    render_404
  end

  def show
    @journals = @issue.visible_journals_with_index
    @changesets = @issue.changesets.visible.preload(:repository, :user).to_a
    @relations = @issue.relations.select {|r| r.other_issue(@issue) && r.other_issue(@issue).visible? }

    if User.current.wants_comments_in_reverse_order?
      @journals.reverse!
      @changesets.reverse!
    end

    if User.current.allowed_to?(:view_time_entries, @project)
      Issue.load_visible_spent_hours([@issue])
      Issue.load_visible_total_spent_hours([@issue])
    end

    respond_to do |format|
      format.html {
        @allowed_statuses = @issue.new_statuses_allowed_to(User.current)
        @priorities = IssuePriority.active
        @time_entry = TimeEntry.new(:issue => @issue, :project => @issue.project)
        @relation = IssueRelation.new
        retrieve_previous_and_next_issue_ids
        render :template => 'issues/show'
      }
      format.api
      format.atom { render :template => 'journals/index', :layout => false, :content_type => 'application/atom+xml' }
      format.pdf  {
        send_file_headers! :type => 'application/pdf', :filename => "#{@project.identifier}-#{@issue.id}.pdf"
      }
    end
  end

  def new
    respond_to do |format|
      format.html { render :action => 'new', :layout => !request.xhr? }
      format.js
    end
  end

  def create
    unless User.current.allowed_to?(:add_issues, @issue.project, :global => true)
      raise ::Unauthorized
    end
    call_hook(:controller_issues_new_before_save, { :params => params, :issue => @issue })
    @issue.save_attachments(params[:attachments] || (params[:issue] && params[:issue][:uploads]))
    if @issue.save
      call_hook(:controller_issues_new_after_save, { :params => params, :issue => @issue})
      respond_to do |format|
        format.html {
          render_attachment_warning_if_needed(@issue)
          flash[:notice] = l(:notice_issue_successful_create, :id => view_context.link_to("##{@issue.id}", issue_path(@issue), :title => @issue.subject))
          redirect_after_create
        }
        format.api  { render :action => 'show', :status => :created, :location => issue_url(@issue) }
      end
      return
    else
      respond_to do |format|
        format.html {
          if @issue.project.nil?
            render_error :status => 422
          else
            render :action => 'new'
          end
        }
        format.api  { render_validation_errors(@issue) }
      end
    end
  end

  def edit
    return unless update_issue_from_params

    respond_to do |format|
      format.html { }
      format.js
    end
  end

  def update
    return unless update_issue_from_params
    @issue.save_attachments(params[:attachments] || (params[:issue] && params[:issue][:uploads]))
    saved = false
    begin
      saved = save_issue_with_child_records
    rescue ActiveRecord::StaleObjectError
      @conflict = true
      if params[:last_journal_id]
        @conflict_journals = @issue.journals_after(params[:last_journal_id]).to_a
        @conflict_journals.reject!(&:private_notes?) unless User.current.allowed_to?(:view_private_notes, @issue.project)
      end
    end

    if saved
      render_attachment_warning_if_needed(@issue)
      flash[:notice] = l(:notice_successful_update) unless @issue.current_journal.new_record?

      respond_to do |format|
        format.html { redirect_back_or_default issue_path(@issue, previous_and_next_issue_ids_params) }
        format.api  { render_api_ok }
      end
    else
      respond_to do |format|
        format.html { render :action => 'edit' }
        format.api  { render_validation_errors(@issue) }
      end
    end
  end

  # Bulk edit/copy a set of issues
  def bulk_edit
    @issues.sort!
    @copy = params[:copy].present?
    @notes = params[:notes]

    if @copy
      unless User.current.allowed_to?(:copy_issues, @projects)
        raise ::Unauthorized
      end
    else
      unless @issues.all?(&:attributes_editable?)
        raise ::Unauthorized
      end
    end

    edited_issues = Issue.where(:id => @issues.map(&:id)).to_a

    @values_by_custom_field = {}
    edited_issues.each do |issue|
      issue.custom_field_values.each do |c|
        if c.value_present?
          @values_by_custom_field[c.custom_field] ||= []
          @values_by_custom_field[c.custom_field] << issue.id
        end
      end
    end

    @allowed_projects = Issue.allowed_target_projects
    if params[:issue]
      @target_project = @allowed_projects.detect {|p| p.id.to_s == params[:issue][:project_id].to_s}
      if @target_project
        target_projects = [@target_project]
        edited_issues.each {|issue| issue.project = @target_project}
      end
    end
    target_projects ||= @projects

    @trackers = target_projects.map {|p| Issue.allowed_target_trackers(p) }.reduce(:&)
    if params[:issue]
      @target_tracker = @trackers.detect {|t| t.id.to_s == params[:issue][:tracker_id].to_s}
      if @target_tracker
        edited_issues.each {|issue| issue.tracker = @target_tracker}
      end
    end

    if @copy
      # Copied issues will get their default statuses
      @available_statuses = []
    else
      @available_statuses = edited_issues.map(&:new_statuses_allowed_to).reduce(:&)
    end
    if params[:issue]
      @target_status = @available_statuses.detect {|t| t.id.to_s == params[:issue][:status_id].to_s}
      if @target_status
        edited_issues.each {|issue| issue.status = @target_status}
      end
    end

    edited_issues.each do |issue|
      issue.custom_field_values.each do |c|
        if c.value_present? && @values_by_custom_field[c.custom_field]
          @values_by_custom_field[c.custom_field].delete(issue.id)
        end
      end
    end
    @values_by_custom_field.delete_if {|k,v| v.blank?}

    @custom_fields = edited_issues.map{|i|i.editable_custom_fields}.reduce(:&).select {|field| field.format.bulk_edit_supported}
    @assignables = target_projects.map(&:assignable_users).reduce(:&)
    @versions = target_projects.map {|p| p.shared_versions.open}.reduce(:&)
    @categories = target_projects.map {|p| p.issue_categories}.reduce(:&)
    if @copy
      @attachments_present = @issues.detect {|i| i.attachments.any?}.present?
      @subtasks_present = @issues.detect {|i| !i.leaf?}.present?
      @watchers_present = User.current.allowed_to?(:add_issue_watchers, @projects) && Watcher.where(:watchable_type => 'Issue', :watchable_id => @issues.map(&:id)).exists?
    end

    @safe_attributes = edited_issues.map(&:safe_attribute_names).reduce(:&)

    @issue_params = params[:issue] || {}
    @issue_params[:custom_field_values] ||= {}
  end

  def bulk_update
    @issues.sort!
    @copy = params[:copy].present?

    attributes = parse_params_for_bulk_update(params[:issue])
    copy_subtasks = (params[:copy_subtasks] == '1')
    copy_attachments = (params[:copy_attachments] == '1')
    copy_watchers = (params[:copy_watchers] == '1')

    if @copy
      unless User.current.allowed_to?(:copy_issues, @projects)
        raise ::Unauthorized
      end
      target_projects = @projects
      if attributes['project_id'].present?
        target_projects = Project.where(:id => attributes['project_id']).to_a
      end
      unless User.current.allowed_to?(:add_issues, target_projects)
        raise ::Unauthorized
      end
      unless User.current.allowed_to?(:add_issue_watchers, @projects)
        copy_watchers = false
      end
    else
      unless @issues.all?(&:attributes_editable?)
        raise ::Unauthorized
      end
    end

    unsaved_issues = []
    saved_issues = []

    if @copy && copy_subtasks
      # Descendant issues will be copied with the parent task
      # Don't copy them twice
      @issues.reject! {|issue| @issues.detect {|other| issue.is_descendant_of?(other)}}
    end

    @issues.each do |orig_issue|
      orig_issue.reload
      if @copy
        issue = orig_issue.copy({},
          :attachments => copy_attachments,
          :subtasks => copy_subtasks,
          :watchers => copy_watchers,
          :link => link_copy?(params[:link_copy])
        )
      else
        issue = orig_issue
      end
      journal = issue.init_journal(User.current, params[:notes])
      issue.safe_attributes = attributes
      call_hook(:controller_issues_bulk_edit_before_save, { :params => params, :issue => issue })
      if issue.save
        saved_issues << issue
      else
        unsaved_issues << orig_issue
      end
    end

    if unsaved_issues.empty?
      flash[:notice] = l(:notice_successful_update) unless saved_issues.empty?
      if params[:follow]
        if @issues.size == 1 && saved_issues.size == 1
          redirect_to issue_path(saved_issues.first)
        elsif saved_issues.map(&:project).uniq.size == 1
          redirect_to project_issues_path(saved_issues.map(&:project).first)
        end
      else
        redirect_back_or_default _project_issues_path(@project)
      end
    else
      @saved_issues = @issues
      @unsaved_issues = unsaved_issues
      @issues = Issue.visible.where(:id => @unsaved_issues.map(&:id)).to_a
      bulk_edit
      render :action => 'bulk_edit'
    end
  end

  def destroy
    raise Unauthorized unless @issues.all?(&:deletable?)

    # all issues and their descendants are about to be deleted
    issues_and_descendants_ids = Issue.self_and_descendants(@issues).pluck(:id)
    time_entries = TimeEntry.where(:issue_id => issues_and_descendants_ids)
    @hours = time_entries.sum(:hours).to_f

    if @hours > 0
      case params[:todo]
      when 'destroy'
        # nothing to do
      when 'nullify'
        if Setting.timelog_required_fields.include?('issue_id')
          flash.now[:error] = l(:field_issue) + " " + ::I18n.t('activerecord.errors.messages.blank')
          return
        else
        time_entries.update_all(:issue_id => nil)
        end
      when 'reassign'
        reassign_to = @project && @project.issues.find_by_id(params[:reassign_to_id])
        if reassign_to.nil?
          flash.now[:error] = l(:error_issue_not_found_in_project)
          return
        elsif issues_and_descendants_ids.include?(reassign_to.id)
          flash.now[:error] = l(:error_cannot_reassign_time_entries_to_an_issue_about_to_be_deleted)
          return
        else
          time_entries.update_all(:issue_id => reassign_to.id, :project_id => reassign_to.project_id)
        end
      else
        # display the destroy form if it's a user request
        return unless api_request?
      end
    end
    @issues.each do |issue|
      begin
        issue.reload.destroy
      rescue ::ActiveRecord::RecordNotFound # raised by #reload if issue no longer exists
        # nothing to do, issue was already deleted (eg. by a parent)
      end
    end
    respond_to do |format|
      format.html { redirect_back_or_default _project_issues_path(@project) }
      format.api  { render_api_ok }
    end
  end

  # Overrides Redmine::MenuManager::MenuController::ClassMethods for
  # when the "New issue" tab is enabled
  def current_menu_item
    if Setting.new_item_menu_tab == '1' && [:new, :create].include?(action_name.to_sym)
      :new_issue
    else
      super
    end
  end

  private

  def retrieve_previous_and_next_issue_ids
    if params[:prev_issue_id].present? || params[:next_issue_id].present?
      @prev_issue_id = params[:prev_issue_id].presence.try(:to_i)
      @next_issue_id = params[:next_issue_id].presence.try(:to_i)
      @issue_position = params[:issue_position].presence.try(:to_i)
      @issue_count = params[:issue_count].presence.try(:to_i)
    else
      retrieve_query_from_session
      if @query
        @per_page = per_page_option
        limit = 500
        issue_ids = @query.issue_ids(:limit => (limit + 1))
        if (idx = issue_ids.index(@issue.id)) && idx < limit
          if issue_ids.size < 500
            @issue_position = idx + 1
            @issue_count = issue_ids.size
          end
          @prev_issue_id = issue_ids[idx - 1] if idx > 0
          @next_issue_id = issue_ids[idx + 1] if idx < (issue_ids.size - 1)
        end
        query_params = @query.as_params
        if @issue_position
          query_params = query_params.merge(:page => (@issue_position / per_page_option) + 1, :per_page => per_page_option)
        end
        @query_path = _project_issues_path(@query.project, query_params)
      end
    end
  end

  def previous_and_next_issue_ids_params
    {
      :prev_issue_id => params[:prev_issue_id],
      :next_issue_id => params[:next_issue_id],
      :issue_position => params[:issue_position],
      :issue_count => params[:issue_count]
    }.reject {|k,v| k.blank?}
  end

  # Used by #edit and #update to set some common instance variables
  # from the params
  def update_issue_from_params
    @time_entry = TimeEntry.new(:issue => @issue, :project => @issue.project)
    if params[:time_entry]
      @time_entry.safe_attributes = params[:time_entry]
    end

    @issue.init_journal(User.current)

    issue_attributes = params[:issue]
    if issue_attributes && params[:conflict_resolution]
      case params[:conflict_resolution]
      when 'overwrite'
        issue_attributes = issue_attributes.dup
        issue_attributes.delete(:lock_version)
      when 'add_notes'
        issue_attributes = issue_attributes.slice(:notes, :private_notes)
      when 'cancel'
        redirect_to issue_path(@issue)
        return false
      end
    end
    @issue.safe_attributes = issue_attributes
    @priorities = IssuePriority.active
    @allowed_statuses = @issue.new_statuses_allowed_to(User.current)
    true
  end

  # Used by #new and #create to build a new issue from the params
  # The new issue will be copied from an existing one if copy_from parameter is given
  def build_new_issue_from_params
    @issue = Issue.new
    if params[:copy_from]
      begin
        @issue.init_journal(User.current)
        @copy_from = Issue.visible.find(params[:copy_from])
        unless User.current.allowed_to?(:copy_issues, @copy_from.project)
          raise ::Unauthorized
        end
        @link_copy = link_copy?(params[:link_copy]) || request.get?
        @copy_attachments = params[:copy_attachments].present? || request.get?
        @copy_subtasks = params[:copy_subtasks].present? || request.get?
        @copy_watchers = User.current.allowed_to?(:add_issue_watchers, @project)
        @issue.copy_from(@copy_from, :attachments => @copy_attachments, :subtasks => @copy_subtasks, :watchers => @copy_watchers, :link => @link_copy)
        @issue.parent_issue_id = @copy_from.parent_id
      rescue ActiveRecord::RecordNotFound
        render_404
        return
      end
    end
    @issue.project = @project
    if request.get?
      @issue.project ||= @issue.allowed_target_projects.first
    end
    @issue.author ||= User.current
    @issue.start_date ||= User.current.today if Setting.default_issue_start_date_to_creation_date?

    attrs = (params[:issue] || {}).deep_dup
    if action_name == 'new' && params[:was_default_status] == attrs[:status_id]
      attrs.delete(:status_id)
    end
    if action_name == 'new' && params[:form_update_triggered_by] == 'issue_project_id'
      # Discard submitted version when changing the project on the issue form
      # so we can use the default version for the new project
      attrs.delete(:fixed_version_id)
    end
    @issue.safe_attributes = attrs

    if @issue.project
      @issue.tracker ||= @issue.allowed_target_trackers.first
      if @issue.tracker.nil?
        if @issue.project.trackers.any?
          # None of the project trackers is allowed to the user
          render_error :message => l(:error_no_tracker_allowed_for_new_issue_in_project), :status => 403
        else
          # Project has no trackers
          render_error l(:error_no_tracker_in_project)
        end
        return false
      end
      if @issue.status.nil?
        render_error l(:error_no_default_issue_status)
        return false
      end
    elsif request.get?
      render_error :message => l(:error_no_projects_with_tracker_allowed_for_new_issue), :status => 403
      return false
    end

    @priorities = IssuePriority.active
    @allowed_statuses = @issue.new_statuses_allowed_to(User.current)
  end

  # Saves @issue and a time_entry from the parameters
  def save_issue_with_child_records
    Issue.transaction do
      if params[:time_entry] && (params[:time_entry][:hours].present? || params[:time_entry][:comments].present?) && User.current.allowed_to?(:log_time, @issue.project)
        time_entry = @time_entry || TimeEntry.new
        time_entry.project = @issue.project
        time_entry.issue = @issue
        time_entry.user = User.current
        time_entry.spent_on = User.current.today
        time_entry.safe_attributes = params[:time_entry]
        @issue.time_entries << time_entry
      end

      call_hook(:controller_issues_edit_before_save, { :params => params, :issue => @issue, :time_entry => time_entry, :journal => @issue.current_journal})
      if @issue.save
        call_hook(:controller_issues_edit_after_save, { :params => params, :issue => @issue, :time_entry => time_entry, :journal => @issue.current_journal})
      else
        raise ActiveRecord::Rollback
      end
    end
  end

  # Returns true if the issue copy should be linked
  # to the original issue
  def link_copy?(param)
    case Setting.link_copied_issue
    when 'yes'
      true
    when 'no'
      false
    when 'ask'
      param == '1'
    end
  end

  # Redirects user after a successful issue creation
  def redirect_after_create
    if params[:continue]
      url_params = {}
      url_params[:issue] = {:tracker_id => @issue.tracker, :parent_issue_id => @issue.parent_issue_id}.reject {|k,v| v.nil?}
      url_params[:back_url] = params[:back_url].presence

      if params[:project_id]
        redirect_to new_project_issue_path(@issue.project, url_params)
      else
        url_params[:issue].merge! :project_id => @issue.project_id
        redirect_to new_issue_path(url_params)
      end
    else
      redirect_back_or_default issue_path(@issue)
    end
  end
end
