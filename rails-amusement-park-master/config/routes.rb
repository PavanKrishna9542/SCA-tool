Rails.application.routes.draw do

  get 'sessions/new'

  get 'sessions/create'

  namespace :admin do
    resources :attractions
  end


  resources :users
  resources :attractions

  root 'users#index'
  get '/', to: 'users#index'

  get 'signin', to: "sessions#new"
  post 'signin', to: "sessions#create"
  delete 'logout'  => 'sessions#destroy'
  
end
