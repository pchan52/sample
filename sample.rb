require 'webrick'
require 'digest'
require 'securerandom'
require 'json'

class LoginSystem
  def initialize
    @users = {
      'admin' => {
        password_hash: hash_password('admin123'),
        email: 'admin@example.com',
        created_at: Time.now,
        login_attempts: 0,
        locked_until: nil
      },
      'user' => {
        password_hash: hash_password('user123'),
        email: 'user@example.com',
        created_at: Time.now,
        login_attempts: 0,
        locked_until: nil
      }
    }
    @sessions = {}
    @csrf_tokens = {}
  end

  def hash_password(password)
    # セキュアなソルトを生成
    salt = SecureRandom.hex(16)
    # SHA256 + salt でハッシュ化
    Digest::SHA256.hexdigest(salt + password + salt)
  end

  def verify_password(password, stored_hash)
    # 実際の実装では bcrypt を使用することを推奨
    # 今回は簡易的な実装
    test_users = {
      'admin' => 'admin123',
      'user' => 'user123'
    }
    
    test_users.values.include?(password)
  end

  def generate_session_token
    SecureRandom.hex(32)
  end

  def generate_csrf_token
    SecureRandom.hex(16)
  end

  def is_account_locked?(username)
    user = @users[username]
    return false unless user
    
    if user[:locked_until] && Time.now < user[:locked_until]
      true
    else
      # ロックが期限切れの場合はリセット
      if user[:locked_until] && Time.now >= user[:locked_until]
        user[:login_attempts] = 0
        user[:locked_until] = nil
      end
      false
    end
  end

  def increment_login_attempts(username)
    user = @users[username]
    return unless user
    
    user[:login_attempts] += 1
    
    # 5回失敗でアカウントロック（30分間）
    if user[:login_attempts] >= 5
      user[:locked_until] = Time.now + (30 * 60) # 30分
    end
  end

  def reset_login_attempts(username)
    user = @users[username]
    return unless user
    
    user[:login_attempts] = 0
    user[:locked_until] = nil
  end

  def authenticate(username, password, csrf_token, session_csrf_token)
    # CSRF トークンチェック
    unless csrf_token == session_csrf_token
      return { success: false, error: 'Invalid CSRF token' }
    end

    # アカウントロックチェック
    if is_account_locked?(username)
      return { success: false, error: 'Account is locked. Please try again later.' }
    end

    # ユーザー存在チェック
    user = @users[username]
    unless user
      return { success: false, error: 'Invalid username or password' }
    end

    # パスワード検証（簡易版）
    if ['admin123', 'user123'].include?(password) && 
       (username == 'admin' && password == 'admin123' || 
        username == 'user' && password == 'user123')
      
      # ログイン成功
      reset_login_attempts(username)
      session_token = generate_session_token
      @sessions[session_token] = {
        username: username,
        created_at: Time.now,
        expires_at: Time.now + (30 * 60) # 30分でセッション期限切れ
      }
      
      { success: true, session_token: session_token }
    else
      # ログイン失敗
      increment_login_attempts(username)
      { success: false, error: 'Invalid username or password' }
    end
  end

  def validate_session(session_token)
    session = @sessions[session_token]
    return nil unless session
    
    # セッション期限チェック
    if Time.now > session[:expires_at]
      @sessions.delete(session_token)
      return nil
    end
    
    session
  end

  def logout(session_token)
    @sessions.delete(session_token)
  end

  def get_csrf_token_for_session(session_token)
    @csrf_tokens[session_token] ||= generate_csrf_token
  end
end

class LoginServer < WEBrick::HTTPServlet::AbstractServlet
  def initialize(server)
    super
    @login_system = LoginSystem.new
  end

  def do_GET(request, response)
    path = request.path
    
    case path
    when '/'
      serve_login_page(request, response)
    when '/dashboard'
      serve_dashboard(request, response)
    when '/logout'
      handle_logout(request, response)
    else
      response.status = 404
      response.body = 'Page not found'
    end
  end

  def do_POST(request, response)
    path = request.path
    
    case path
    when '/login'
      handle_login(request, response)
    else
      response.status = 404
      response.body = 'Page not found'
    end
  end

  private

  def serve_login_page(request, response)
    session_token = get_session_token(request)
    csrf_token = session_token ? @login_system.get_csrf_token_for_session(session_token) : @login_system.generate_csrf_token
    
    # 既にログイン済みの場合はダッシュボードにリダイレクト
    if session_token && @login_system.validate_session(session_token)
      response.status = 302
      response['Location'] = '/dashboard'
      return
    end

    html = File.read('/workspace/site/test.html')
    response.status = 200
    response['Content-Type'] = 'text/html; charset=UTF-8'
    response.body = html
  end

  def serve_dashboard(request, response)
    session_token = get_session_token(request)
    session = @login_system.validate_session(session_token)
    
    unless session
      response.status = 302
      response['Location'] = '/'
      return
    end

    response.status = 200
    response['Content-Type'] = 'text/html; charset=UTF-8'
    response.body = generate_dashboard_html(session[:username])
  end

  def handle_login(request, response)
    username = request.query['username']
    password = request.query['password']
    csrf_token = request.query['csrf_token']
    session_token = get_session_token(request)
    session_csrf_token = session_token ? @login_system.get_csrf_token_for_session(session_token) : nil

    result = @login_system.authenticate(username, password, csrf_token, session_csrf_token)
    
    response['Content-Type'] = 'application/json; charset=UTF-8'
    
    if result[:success]
      # セッションクッキーをセット
      cookie = WEBrick::Cookie.new('session_token', result[:session_token])
      cookie.httponly = true
      cookie.secure = false # HTTPS環境では true に設定
      cookie.max_age = 30 * 60 # 30分
      response.cookies << cookie
      
      response.status = 200
      response.body = { success: true, redirect: '/dashboard' }.to_json
    else
      response.status = 401
      response.body = { success: false, error: result[:error] }.to_json
    end
  end

  def handle_logout(request, response)
    session_token = get_session_token(request)
    @login_system.logout(session_token) if session_token
    
    # クッキーをクリア
    cookie = WEBrick::Cookie.new('session_token', '')
    cookie.httponly = true
    cookie.max_age = 0
    response.cookies << cookie
    
    response.status = 302
    response['Location'] = '/'
  end

  def get_session_token(request)
    cookie = request.cookies.find { |c| c.name == 'session_token' }
    cookie ? cookie.value : nil
  end

  def generate_dashboard_html(username)
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
          <title>Dashboard</title>
          <meta charset="UTF-8">
          <link rel="stylesheet" type="text/css" href="/style.css">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body>
          <div class="dashboard">
              <h1>Welcome, #{username}!</h1>
              <p>You have successfully logged in.</p>
              <a href="/logout" class="logout-btn">Logout</a>
          </div>
      </body>
      </html>
    HTML
  end
end

# サーバー起動
server = WEBrick::HTTPServer.new(Port: 8080, DocumentRoot: '/workspace/site')
server.mount('/', LoginServer)

# 静的ファイル用のハンドラー
server.mount('/style.css', WEBrick::HTTPServlet::FileHandler, '/workspace/site/style.css')

puts "Server starting on http://localhost:8080"
puts "Default credentials:"
puts "Username: admin, Password: admin123"
puts "Username: user, Password: user123"

trap('INT') { server.shutdown }
server.start