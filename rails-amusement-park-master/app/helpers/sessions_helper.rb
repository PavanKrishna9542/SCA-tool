module SessionsHelper

  def current_user
    binding.pry
    @current_user ||= User.find(session[:user_id])
    # session[:user_id] ||= nil
  end

end
