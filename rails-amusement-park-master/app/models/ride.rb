class Ride < ActiveRecord::Base
  # write associations here
  belongs_to :attraction
  belongs_to :user

  def take_ride
    if ((self.user.tickets - self.attraction.tickets) < 0) && (self.user.height < self.attraction.min_height)
       return "Sorry. You do not have enough tickets the #{self.attraction.name}. You are not tall enough to ride the #{self.attraction.name}."
    elsif self.user.tickets - self.attraction.tickets < 0
        return "Sorry. You do not have enough tickets the #{self.attraction.name}."
    elsif self.user.height < self.attraction.min_height
        return "Sorry. You are not tall enough to ride the #{self.attraction.name}."
    else
      self.user.tickets -= self.attraction.tickets
      self.user.nausea += self.attraction.nausea_rating
      self.user.happiness += self.attraction.happiness_rating
      self.user.save
      return "Thanks for riding the #{self.attraction.name}!"
    end
  end

end
