from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, Email

class QuestionForm(FlaskForm):
	                # 화면에서 출력할 해당 필드의 라벨, 필수 항목 체크 여부
    # <label for='subject'> 제목 </label>
    # <input type=text name='subject' required> 
    subject = StringField('제목', validators=[DataRequired('제목은 필수입력 항목입니다.')])
    # subject = StringField('제목')
    # <label for='content'> 내용 </label>
    # <input typt=text-area name='content' required> 

    content = TextAreaField('내용', validators=[DataRequired()])

class AnswerForm(FlaskForm):
    content = TextAreaField('내용', validators=[DataRequired()])

class UserCreateForm(FlaskForm):
    username = StringField('사용자이름', validators=[DataRequired(), Length(min=3, max=25)])
    password1 = PasswordField('비밀번호', validators=[
        DataRequired(), EqualTo('password2', '비밀번호가 일치하지 않습니다')])
    password2 = PasswordField('비밀번호확인', validators=[DataRequired()])
    email = EmailField('이메일', validators=[DataRequired(), Email()])

class UserLoginForm(FlaskForm):
    username = StringField('사용자이름', validators=[DataRequired(), Length(min=5, max=8, message="ID는 5글자 이상 8글자 미만이어야 합니다.")])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    