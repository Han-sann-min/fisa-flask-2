from flask import Blueprint, redirect, render_template, url_for, g, flash, request, get_flashed_messages
from flask_login import current_user
from ..forms import AnswerForm
from test import db
from datetime import datetime
from ..models import Answer
from test.views.auth_views import login_required

answer = Blueprint('answer', __name__, url_prefix="/answer")

@answer.route("/create/<int:question_id>", methods=["GET", "POST"])
def create(question_id):
    # AnswerForm으로 화면에서 받은 데이터를
    form = AnswerForm()
    # 우리가 요청한 조건에 맞으면
    if form.validate_on_submit():
        a = Answer(question_id=question_id, content=form.content.data, create_date=datetime.now(), user_id=g.user.id)
        # DB에 저장
        db.session.add(a)   
        db.session.commit()
    # 후 원래 페이지로 redirect ('submit.html')
        return redirect (url_for ('board.post_detail', question_id=question_id))
    # 빈 화면으로 넘기기
    return render_template('question/question_detail.html', question_id=question_id, form=form)

@answer.route("/modify/<int:answer_id>", methods=('GET', 'POST'))
@login_required
def modify(answer_id):
    # 답변을 가져온다
    answer = Answer.query.get_or_404(answer_id)
    question_id = answer.question_id
    # 지금 답변을 변경하려는 사람(로그인한사람)이 작성자인지 확인한다
    if g.user != answer.user: 
        flash('수정권한이 없습니다')
        return redirect(url_for('board.post_detail', question_id=question_id))
    # 아니면 flash로 에러메시지 전달
    # 맞으면, post로 값이 왔으면
    if request.method == 'POST':
        form =AnswerForm()
        if form.validate_on_submit():
            form.populate_obj(answer) # 화면에 원래 db에서 꺼낸 값을 변경해서 뿌림
            db.session.commit()
            return redirect(url_for('board.post_detail', question_id=question_id))
            # 값을 수정하여 다시 session에 commit
    else: # GET으로 요청이 왔을 때
        form = AnswerForm(obj=answer)
    # modify라는 변수 사용하여 있으면 answer.modify로 동작하도록 변경
    return render_template('answer/answer_form.html', form=form, \
    											answer_id=answer_id, modify=True)


@answer.route("/delete/<int:answer_id>")
@login_required
def delete(answer_id):
    # 글을 가져옴
    answer = Answer.query.get_or_404(answer_id)
    # 현재 접속한 사용자와 글의 작성자가 일치하는지 확인
    question_id= answer.question_id
    if g.user != answer.user: 
        flash('댓글 삭제 권한이 없습니다')
    #     일치하지 않으면 -> 삭제권한이 없습니다 메시지 출력
        return redirect(url_for('board.post_detail', question_id=question_id))
    #     원래 글로 되돌아감
    db.session.delete(answer)
    db.session.commit()
    # 커밋
    # question_list로 되돌아감 
    return redirect(url_for('board.post_detail', question_id=question_id))