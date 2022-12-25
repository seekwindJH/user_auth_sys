from flask import Flask, request, session, redirect, render_template
from flask_session import Session
import pymysql
from redis import Redis
from hashlib import md5
from threading import Condition
from config import mysql_config, redis_config

app = Flask('uid_sys', static_folder='static', template_folder='templates')
app.run()

password_salt = 'ACFCAA19-EC5C-2317-C0A0-00C7769272E5'

'''实现了一个轻量级数据库连接池'''
# docker run -itd --name mysql-test -p 13306:3306 -e MYSQL_ROOT_PASSWORD=c9M2t_f3jg* mysql:5.7.40
connections_pool = [pymysql.connect(
    host=mysql_config['host'], port=mysql_config['port'], user=mysql_config['user'], password=mysql_config['password'], db=mysql_config['db'], charset=mysql_config['charset']) for _ in range(mysql_config['pool_size'])]
pool_condition = Condition()


def get_mysql_connection():
    with pool_condition:
        while not connections_pool:
            pool_condition.wait()
        _connection = connections_pool.pop()
    return _connection


def return_mysql_connection(connection: pymysql.Connection):
    with pool_condition:
        connections_pool.append(connection)
        pool_condition.notify()


''''''

'''session存储于Redis中'''
# docker run -d --name redis-test -p 16379:6379 redis:6.2.6
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis(
    host=redis_config['host'], port=redis_config['port'], password=redis_config['password'])
app.config["SECRET_KEY"] = b'&\x8b=H7`y\x81*\x89DPS \xd5\x80'
app.config['SESSION_USE_SIGNER'] = True  # 是否强制加盐，混淆session
app.config['SESSION_PERMANENT'] = True  # sessons是否长期有效，false，则关闭浏览器，session失效
# session长期有效，则设定session生命周期，整数秒
app.config['PERMANENT_SESSION_LIFETIME'] = redis_config['lifetime']
Session(app)
''''''

'''控制层'''


@app.route('/')
def hello_world():
    return 'UID_SYS'


@app.route('/login', methods=['get'])
def login_page():
    dst_url = request.args.get('dst_url', '')
    session['dst_url'] = dst_url
    # 如果该用户已登录，则重定向至dst_url
    if 'auth_name' in session and dst_url:
        return redirect(dst_url)
    # 返回一个登录页面
    return render_template('login.html', is_login_page=True)


@app.route('/register', methods=['get'])
def register_page():
    dst_url = request.args.get('dst_url', '')
    session['dst_url'] = dst_url
    return render_template('login.html', is_login_page=False)


@app.route('/login', methods=['post'])
def login_auth():
    dst_url = session['dst_url']
    auth_name = request.form['auth_name']
    password = request.form['password']
    password_digest = md5(
        (auth_name + password_salt + password).encode()).hexdigest()
    mysql_connection = get_mysql_connection()
    cur = mysql_connection.cursor()
    try:
        cur.execute("SELECT 1 FROM auth_user WHERE auth_name=%s AND password_digest=%s AND enable_flag='Y'",
                    (auth_name, password_digest))
        if cur.fetchone():
            session['auth_name'] = auth_name
            cur.execute(
                'UPDATE auth_user SET login_times=login_times+1 WHERE auth_name=%s', (auth_name))
        else:
            session.pop('auth_name')
    except Exception as e:
        print(e)
        return render_template('login.html', is_login_page=True, msg='数据库内部异常')
    finally:
        cur.close()
        mysql_connection.commit()
        return_mysql_connection(mysql_connection)
    if dst_url and session['auth_name']:
        return redirect(dst_url)
    elif session['auth_name']:
        return render_template('login.html', is_login_page=True, msg='登录成功')
    else:
        return render_template('login.html', is_login_page=True, msg='登录失败，可能是以下原因：账号密码错误，账号不存在或未启用')


@app.route('/register', methods=['post'])
def register_auth():
    dst_url = session['dst_url']
    auth_name = request.form['auth_name']
    password = request.form['password']
    password_digest = md5(
        (auth_name + password_salt + password).encode()).hexdigest()
    mysql_connection = get_mysql_connection()
    cur = mysql_connection.cursor()
    try:
        cur.execute("INSERT INTO core_sys.auth_user (auth_name, enable_flag, password_digest, regtime, login_times, reg_dst_url) VALUES (%s, 'N', %s, NOW(), 0, %s)",
                    (auth_name, password_digest, dst_url))
    except Exception as e:
        print(e)
        return render_template('login.html', is_login_page=False, msg='数据库内部异常')
    finally:
        cur.close()
        mysql_connection.commit()
        return_mysql_connection(mysql_connection)
    return render_template('login.html', is_login_page=False, msg='注册已提交，待管理员审核')


@app.route('/logout', methods=['post'])
def logout():
    if 'auth_name' not in session:
        return render_template('login.html', is_login_page=True, msg='已处于未登录状态')
    return render_template('login.html', is_login_page=True, msg=('{}已登出' % session.pop('auth_name')))


''''''
