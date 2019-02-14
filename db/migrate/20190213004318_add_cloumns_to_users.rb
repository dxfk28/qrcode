class AddCloumnsToUsers < ActiveRecord::Migration[5.2]
  def change
  	add_column :users, :s_id, :boolean
  	add_column :users, :up, :boolean
  	add_column :users, :down, :boolean
  	add_column :users, :serach, :boolean
  	add_column :users, :preview, :boolean
  	add_column :users, :department, :string
  end
end
