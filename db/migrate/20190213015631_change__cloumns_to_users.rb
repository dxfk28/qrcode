class ChangeCloumnsToUsers < ActiveRecord::Migration[5.2]
  def change
  	remove_column :users, :s_id, :boolean
  	add_column :users, :service, :boolean
  end
end
