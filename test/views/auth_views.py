from flask import Blueprint, request, render_template, flash, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
from test.models import User
from test import db
from test.forms import UserCreateForm, UserLoginForm
import functools

auth = Blueprint('auth', __name__, url_prefix="/auth")
# __init__ 의 create_app 안에 등록


# 회원 가입 - signup
@auth.route("/signup", methods=['GET', 'POST'])
def signup():
    #1. 폼을 가져온다
    form = UserCreateForm()

    ## update와 유사한 로직으로 작동합니다 
    #2-1. 폼의 유효성을 확인한다 & db에 해당하는 사용자이름이 있는지도 확인
    if form.validate_on_submit() and request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            #2-1-1. db의 user 테이블에 값을 넣는다  
            hashed_password = generate_password_hash(form.password1.data)
            user = User(username=form.username.data, \
                        password=hashed_password, \
                        email=form.email.data)                                                 
            db.session.add(user)
            db.session.commit()
            return redirect( url_for( 'main.index' ) )
        #2-1-2. 이미 존재하는 사용자입니다
        else:
            flash('이미 가입한 아이디입니다')
    #2-2. 다시 auth/signup.html로 이동시킵니다.
    return render_template('auth/signup.html', form=form)

# signup 함수와 비슷하게 동작
# post로 값이 들어오면 비밀번호 일치 여부에 따라 로그인
@auth.route('/login/', methods=('GET', 'POST'))
def login():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        error = None
				# 폼 입력으로 받은 username으로 데이터베이스에 해당 사용자가 있는지를 검사한다. 만약 사용자가 없으면 "존재하지 않는 사용자입니다."라는 오류를 발생시키고, 사용자가 있다면 폼 입력으로 받은 password와 check_password_hash 함수를 사용하여 데이터베이스의 비밀번호와 일치하는지를 비교합니다.
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            error = "존재하지 않는 사용자입니다."
        elif not check_password_hash(user.password, form.password.data):
            error = "비밀번호가 올바르지 않습니다."
        if error is None:
            # 사용자도 존재하고 비밀번호도 일치한다면 플라스크 세션(session)에 사용자 정보를 저장합니다.

						# 세션에 user_id라는 객체 생성
            session.clear()
            session['user_id'] = user.id
            _next = request.args.get('next', '')
            if _next:
                return redirect(_next)
            else:
                return redirect(url_for('main.index'))
        flash(error)
    return render_template('auth/login.html', form=form)


@auth.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            _next = request.url if request.method == 'GET' else ''
            return redirect(url_for('auth.login', next=_next))
        return view(*args, **kwargs)
    return wrapped_view

@auth.route('/logout/')
def logout():
    session.clear()
    return redirect(url_for('main.index'))