class SessionsController < ApplicationController
  def new
  end

  def create
    @user = User.find(params[:user][:id])
    session[:user_id] = @user.id
    redirect_to user_path(@user)
  end

  def destroy
    @user = User.find(session[:user_id])
    session.delete :user_id
    redirect_to '/'
  end
end
