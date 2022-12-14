module UsersHelper

  def admin_access
    if @user.admin
      "ADMIN"
    end
  end



end
