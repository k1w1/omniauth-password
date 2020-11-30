module OmniAuth
  module Strategies
    class Password
      include OmniAuth::Strategy

      option :user_model, nil # default set to 'User' below
      option :login_field, :email
      option :login_transform, :to_s

      def request_phase
        redirect "/session/new"
      end

      def callback_phase
        return fail!(:invalid_credentials) unless user.try(:authenticate, password)
        super
      end

      def user
        @user ||= user_model.send("find_by_#{options[:login_field]}", login)
      end

      def user_model
        options[:user_model] || ::User
      end

      def login
        if request[:sessions]
          request[:sessions][options[:login_field].to_s].to_s.send(options[:login_transform])
        else
          ''
        end
      end

      def password
        if request[:sessions]
          request[:sessions]['password']
        else
          ''
        end
      end

      uid do
        user.password_digest
      end

    end
  end
end
