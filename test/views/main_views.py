from flask import Blueprint, render_template
from ..models import Question
import logging # 로그를 기록할 페이지에 logging 모듈 import 

# 우리가 부를 이름, flask 프레임워크가 찾을 이름, 라우팅주소
bp = Blueprint('main', __name__, url_prefix="/")

logger = logging.getLogger("flask.app")  # logger 객체에 우리가 사용할 로거를 옵션으로 줍니다

# 첫번째 blueprint부터 찾기 때문에 board를 쓸 수 없게 됩니다 
# @bp.route("/", defaults={"var":'', "var2":""}) # 여러개의 route 어노테이션을 하나의 메서드에 얹어서 쓸 수도 있다
# @bp.route("/<var>/<var2>")  /짱구 #대부분 uri는 str로 받기 때문에 str은 생략 # localhost:5000/yeonji  -> hello yeonji가 출력되도록 
@bp.route("/")
def index():
    logger.debug("DEBUG 수준의 메시지")
    logger.info("INFO 수준의 메시지")
    logger.warning("WARNING 수준의 메시지")
    logger.error("ERROR 수준의 메시지")
    return render_template("index.html")

@bp.route("/bye")
def bye():
    return f'BYE'