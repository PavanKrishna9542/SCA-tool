module AttractionsHelper
  def admin_attraction_link
    user = User.find(session[:user_id])
    if user.admin
      link_to "New Attraction", new_attraction_path
    end
  end

  def admin_attraction_show(attraction)
    user = User.find(session[:user_id])
    if user.admin
      link_to "Show #{attraction.name}", attraction_path(attraction)
    else
      button_to "Go on #{attraction.name}", attraction_path(attraction), method: :get
    end
  end

  def admin_edit_attraction
    @user = User.find(session[:user_id])
    if @user.admin
      link_to "Edit Attraction", edit_attraction_path(@attraction)
    # else
    #   form_for @user do |f|
    #     binding.pry
    #     f.text_field :name
    #     hidden_field_tag('attraction_id', "#{params[:id]}")
    #     f.hidden_field :attraction_id, :value => @attraction.id
    #     f.submit "Go on this ride"
    #   end
    end
  end

  def go_on_attraction_link(attraction)
    @user = User.find(session[:user_id])
    if @user.admin == false
      link_to "Go on " + attraction.name, attraction_path(attraction)
    end
  end
end
