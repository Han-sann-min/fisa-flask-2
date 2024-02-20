from flask import Blueprint, render_template, url_for, redirect, request, g, flash, get_flashed_messages
from ..models import Question, Answer
from ..forms import QuestionForm, AnswerForm
from datetime import datetime
from test import db
from test.views.auth_views import login_required

# 우리가 부를 이름, flask 프레임워크가 찾을 이름, 라우팅주소
board = Blueprint('board', __name__, url_prefix="/board")

@board.route("/list")
def post_list():
    page = request.args.get('page', type=int, default=1)
    question_list = Question.query.order_by(Question.create_date.desc())
    question_list = question_list.paginate(page=page, per_page=10)
    return render_template("question/question_list.html", question_list=question_list)

# board/detail/1 2 3 4  -> question_detail.html로 각 글의 실제 세부내용을 전달하고 싶어요
@board.route("/detail/<int:question_id>") # question_id 변수로 받은 값을 
def post_detail(question_id): # 함수의 파라미터로 전달
    # question = Question.query.get(question_id) # 모델에서 특정 번호(id)를 통해 값을 조회
    question = Question.query.get_or_404(question_id)
    form = AnswerForm()
    return render_template("question/question_detail.html", question = question,  question_id = question_id, form=form)


@board.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    # 폼을 받는다
    form = QuestionForm()

    # 폼에 온 양식이 우리가 forms.py에 작성한 양식과 일치하는지 확인한다
    if form.validate_on_submit():
    # 일치하면 성공을 의미하는 주소로 전달한다
        # 실제 db에 값을 넣는 로직이 없습니다

       q = Question(subject=form.subject.data, \
                   content=form.content.data, \
                    create_date=datetime.now(), \
                    user_id=g.user.id)                                              
       db.session.add(q)
       db.session.commit()
       return redirect( url_for( 'board.post_list' ) )
       
       
    #    return render_template( 'question/question_list.html' )
    
    return render_template('question/question_form.html', form=form)


# @board.route("/create", methods=['GET', 'POST'])
# def create():
    # 폼을 받는다
  #  form 
    # 폼에 온 양식이 우리가 forms.py에 작성한 양식과 일치하는지 확인한다
    # 일치하면 성공을 의미하는 주소로 전달한다

@board.route("/modify/<int:question_id>", methods=('GET', 'POST'))
@login_required
def modify(question_id):
    # 글을 가져온다
    question = Question.query.get_or_404(question_id)
    # 지금 글을 변경하려는 사람(로그인한사람)이 작성자인지 확인한다
    if g.user != question.user: 
        flash('수정권한이 없습니다')
        return redirect(url_for('board.post_list'))
    # 아니면 flash로 에러메시지 전달
    # 맞으면, post로 값이 왔으면
    if request.method == 'POST':
        form = QuestionForm()
        if form.validate_on_submit():
            form.populate_obj(question) # 화면에 원래 db에서 꺼낸 값을 변경해서 뿌림
            db.session.commit()
            return redirect(url_for('board.post_detail', question_id=question_id))
            # 값을 수정하여 다시 session에 commit
    else: # GET으로 요청이 왔을 때
        form = QuestionForm(obj=question)

    get_flashed_messages()
    return render_template('question/question_form.html', form=form)
    # 원래 화면으로 redirect

@board.route("/delete/<int:question_id>")
@login_required
def delete(question_id):
    question = Question.query.get_or_404(question_id)

    # 게시글 작성자인지 확인
    if question.user != g.user:
        flash("게시글을 삭제할 권한이 없습니다.", "danger")
        return redirect(url_for('board.post_list'))  # 게시판 홈으로 리다이렉트

    else:
        # 게시글 삭제 처리
        db.session.delete(question)
        db.session.commit()
        flash("게시글이 삭제되었습니다.", "success")
        return redirect(url_for('board.post_list'))  # 게시판 홈으로 리다이렉트