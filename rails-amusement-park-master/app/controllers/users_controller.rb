class UsersController < ApplicationController

  def index

  end

  def new
    @user = User.new
  end

  def create
    user = User.create(user_params)
    session[:user_id] = user.id
    redirect_to user_path(user)
  end

  def show
    @user = User.find(params[:id])
  end

  def edit
    @user = User.find(params[:id])
    redirect_to user_path(@user)
  end

  def update
    @user = User.find(params[:id])
    ride = @user.rides.create(attraction_id: params[:attraction_id])
    flash[:alert] = ride.take_ride
    redirect_to user_path(@user)
  end

  def destroy
    @user = User.find(params[:id])
    redirect_to users_path
  end

  private

  def user_params
    params.require(:user).permit(:name, :nausea, :happiness, :tickets, :height, :admin)
  end

end
